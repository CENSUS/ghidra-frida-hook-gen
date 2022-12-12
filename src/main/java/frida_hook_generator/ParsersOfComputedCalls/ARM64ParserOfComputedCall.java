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

package frida_hook_generator.ParsersOfComputedCalls;

import java.util.ArrayList;

import docking.action.KeyBindingType;
import frida_hook_generator.ParserOfComputedCalls;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

/*This class basically returns the argument to BLR <arg> in ARM64, translated into frida code. Much simpler than x64.*/
public class ARM64ParserOfComputedCall implements ParserOfComputedCalls{

	private Program incoming_program;
	private Language current_program_language;
	private Processor current_program_processor;
	private String incoming_module_name_sanitized;
	
	public ARM64ParserOfComputedCall(Program incoming_program, String incoming_module_name_sanitized) {
		this.incoming_program=incoming_program;
		this.current_program_language = this.incoming_program.getLanguage();
		this.current_program_processor = this.current_program_language.getProcessor();
		this.incoming_module_name_sanitized=incoming_module_name_sanitized;
	}
	
	
	public String create_frida_code_for_call_arg(String mnemonic,String arg)
	{
		String retval="";
		String arg_str_possibly_altered=arg;
		
		if (arg=="")
		{
			return "";
		}
		arg=arg.trim();
		
		if (mnemonic == "blr" || mnemonic == "br" || mnemonic == "bx")
		{
			arg_str_possibly_altered=arg;
		}
		if (mnemonic == "blraaz")
		{
			arg_str_possibly_altered=arg+".strip(\"ia\")";
		}
		if (mnemonic == "blrabz")
		{
			arg_str_possibly_altered=arg+".strip(\"ib\")";
		}
		//blraa, blrab not yet supported
		
		if (arg.matches("x[0-9]+$"))
		{
			retval+="(this.context."+arg_str_possibly_altered.toLowerCase()+")";
		}
		else
		{
			return "";
		}
		
		return retval;
	}	
}
