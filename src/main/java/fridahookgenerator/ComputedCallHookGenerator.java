/* 
 * BSD 2-Clause License
 *
 * Copyright (c) 2022, CENSUS
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package fridahookgenerator;

import fridahookgenerator.ParsersOfComputedCalls.ARM32ParserOfComputedCall;
import fridahookgenerator.ParsersOfComputedCalls.ARM64ParserOfComputedCall;
import fridahookgenerator.ParsersOfComputedCalls.X86ParserOfComputedCall;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

public class ComputedCallHookGenerator {

	private HookGenerator incoming_hook_generator;
	private Program incoming_program;
	private Language current_program_language;
	private Processor current_program_processor;
	private Address incoming_address;
	private Instruction incoming_instruction;
	private String arg_of_call;
	private String mnemonic_of_command;
	private String incoming_module_name_sanitized;
	private ParserOfComputedCalls parser_of_computed_calls;

	public ComputedCallHookGenerator(HookGenerator incoming_hook_generator,Program incoming_program, Address incoming_address, Instruction incoming_instruction, String mnemonic_of_command, String arg_of_call, String incoming_module_name_sanitized) {
		this.incoming_hook_generator=incoming_hook_generator;
		this.incoming_program=incoming_program;
		this.current_program_language = this.incoming_program.getLanguage();
		this.current_program_processor = this.current_program_language.getProcessor();
		this.incoming_address=incoming_address;
		this.incoming_instruction=incoming_instruction;
		this.mnemonic_of_command=mnemonic_of_command;
		this.arg_of_call=arg_of_call;
		this.incoming_module_name_sanitized=incoming_module_name_sanitized;
		if (this.current_program_language.getLanguageID().toString().indexOf("x86:LE:")>=0)
		{
			parser_of_computed_calls=new X86ParserOfComputedCall(this.incoming_program,this.incoming_module_name_sanitized);
		}
		else if (this.current_program_language.getLanguageID().toString().indexOf("AARCH64:LE:64")>=0)
		{
			parser_of_computed_calls=new ARM64ParserOfComputedCall(this.incoming_program,this.incoming_module_name_sanitized);
		}
		else if (this.current_program_language.getLanguageID().toString().indexOf("ARM:LE:32")>=0)
		{
			parser_of_computed_calls=new ARM32ParserOfComputedCall(this.incoming_program,this.incoming_module_name_sanitized);
		}
		else
		{
			parser_of_computed_calls=null;
		}
	}
	
	/*
	 * The register_context_is_available flag tells whether the registers of the hooked thread can be read at the point
	 * where this code is injected. It is true everywhere at the moment, including inside the NativeCallback of an
	 * Interceptor.replace(), which is emitted as a normal function so that frida binds the invocation context to it.
	 * Careful: if that NativeCallback ever becomes an arrow function again it will have no "this" of its own, the context
	 * will be unavailable, and this has to be false for it. A comment is then emitted instead of code that would throw.
	 */
	public String provide_hook_code(String spaces, Boolean register_context_is_available)
	{
		String retval="";
		String sanitized_addr=this.incoming_hook_generator.utils.return_sanitized_address_str_for_variable_name(this.incoming_address);

		if (this.parser_of_computed_calls==null)
		{
			//Unsupported architecture
			return spaces+"//The destination of the computed "+this.mnemonic_of_command+" at address "+this.incoming_address+" is not printed, the architecture is not supported\n";
		}

		if (!register_context_is_available.booleanValue())
		{
			return spaces+"//The destination of the computed "+this.mnemonic_of_command+" at address "+this.incoming_address+" cannot be printed, because Interceptor.replace() is used for this function and the registers are not available\n";
		}

		String frida_code_for_the_target_address=this.parser_of_computed_calls.create_frida_code_for_call_arg(this.mnemonic_of_command ,this.arg_of_call, this.incoming_instruction);
		if (frida_code_for_the_target_address==null || frida_code_for_the_target_address.equals(""))
		{
			//The argument could not be translated. Careful: an empty string must never be emitted as code, it would produce a syntax error in the generated script
			return spaces+"//The destination of the computed \""+this.mnemonic_of_command+" "+this.arg_of_call+"\" at address "+this.incoming_address+" could not be translated into frida code\n";
		}

		retval+= spaces+"var calculated_target_address_for_initial_address_"+sanitized_addr+"="+frida_code_for_the_target_address+";\n";
		retval+= spaces+"//Find the module in which the target address falls. The module map is created once, before the hooks, and it is only updated when a lookup fails\n";
		retval+= spaces+"var module_containing_target_address=modulemap_for_all_modules.find(calculated_target_address_for_initial_address_"+sanitized_addr+");\n";
		retval+= spaces+"if (module_containing_target_address==null)\n";
		retval+= spaces+"{\n";
		retval+= spaces+"    modulemap_for_all_modules.update(); //the target may belong to a module that was loaded after the map was created\n";
		retval+= spaces+"    module_containing_target_address=modulemap_for_all_modules.find(calculated_target_address_for_initial_address_"+sanitized_addr+");\n";
		retval+= spaces+"}\n";
		retval+= spaces+"if (module_containing_target_address!=null)\n";
		retval+= spaces+"{\n";
		retval+= spaces+"    var offset_from_module_start_for_target_address_for_initial_address_"+sanitized_addr+"=calculated_target_address_for_initial_address_"+sanitized_addr+".sub(module_containing_target_address.base);\n";
		retval+= spaces+"    console.log("+this.incoming_hook_generator.utils.tid_and_indent_code()+"\"Next destination (after the "+this.mnemonic_of_command+" at address "+this.incoming_address+" ) will be to address \"+calculated_target_address_for_initial_address_"+sanitized_addr+"+\", which has offset \"+offset_from_module_start_for_target_address_for_initial_address_"+sanitized_addr+"+\" relative to the module \"+ JSON.stringify(module_containing_target_address));\n";
		retval+= spaces+"    console.log("+this.incoming_hook_generator.utils.tid_and_indent_code()+"\"Debug information on the target address: \"+JSON.stringify(DebugSymbol.fromAddress(calculated_target_address_for_initial_address_"+sanitized_addr+")));\n";
		retval+= spaces+"    //Interceptor.attach(calculated_target_address_for_initial_address_"+sanitized_addr+",function(){console.log(\"Reached target addess from computed call\")})\n";
		retval+= spaces+"}\n";
		retval+= spaces+"else\n";
		retval+= spaces+"{\n";
		retval+= spaces+"    console.log("+this.incoming_hook_generator.utils.tid_and_indent_code()+"\"calculated target address \"+calculated_target_address_for_initial_address_"+sanitized_addr+"+\" does not fall inside any of the known modules\");\n";
		retval+= spaces+"}\n";
		return retval;
	}
	
}
