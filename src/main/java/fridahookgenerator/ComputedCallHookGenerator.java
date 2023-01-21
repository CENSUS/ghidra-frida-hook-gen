package fridahookgenerator;

import fridahookgenerator.ParsersOfComputedCalls.ARM64ParserOfComputedCall;
import fridahookgenerator.ParsersOfComputedCalls.X86ParserOfComputedCall;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;

public class ComputedCallHookGenerator {

	private Program incoming_program;
	private Language current_program_language;
	private Processor current_program_processor;
	private Address incoming_address;
	private String arg_of_call;
	private String mnemonic_of_command;
	private String incoming_module_name_sanitized;
	private ParserOfComputedCalls parser_of_computed_calls;
	
	public ComputedCallHookGenerator(Program incoming_program, Address incoming_address, String mnemonic_of_command, String arg_of_call, String incoming_module_name) {
		this.incoming_program=incoming_program;
		this.current_program_language = this.incoming_program.getLanguage();
		this.current_program_processor = this.current_program_language.getProcessor();
		this.incoming_address=incoming_address;
		this.mnemonic_of_command=mnemonic_of_command;
		this.arg_of_call=arg_of_call;
		this.incoming_module_name_sanitized=incoming_module_name;
		if (this.current_program_language.getLanguageID().toString().indexOf("x86:LE:")>=0)
		{
			parser_of_computed_calls=new X86ParserOfComputedCall(this.incoming_program,this.incoming_module_name_sanitized);
		}
		else if (this.current_program_language.getLanguageID().toString().indexOf("AARCH64:LE:64")>=0)
		{
			parser_of_computed_calls=new ARM64ParserOfComputedCall(this.incoming_program,this.incoming_module_name_sanitized);
		}
		else
		{
			parser_of_computed_calls=null;
		}
	}
	
	public String provide_hook_code(String spaces)
	{
		String retval="";
	
		if (this.parser_of_computed_calls==null)
		{
			//Unsupported architecture
			return "";
		}
			
		
		
		retval+= spaces+"var calculated_target_address_for_initial_address_"+this.incoming_address+"="+this.parser_of_computed_calls.create_frida_code_for_call_arg(this.mnemonic_of_command ,this.arg_of_call)+";\n";
		retval+= spaces+"//Find the module in which the target address falls\n";
		retval+= spaces+"var modulemap_for_all_modules=new ModuleMap();\n";
		retval+= spaces+"var module_containing_target_address=modulemap_for_all_modules.find(calculated_target_address_for_initial_address_"+this.incoming_address+");\n";
		retval+= spaces+"if (module_containing_target_address!=null)\n";
		retval+= spaces+"{\n";
		retval+= spaces+"    var offset_from_module_start_for_target_address_for_initial_address_"+this.incoming_address+"=calculated_target_address_for_initial_address_"+this.incoming_address+".sub(module_containing_target_address.base);\n";
		retval+= spaces+"    console.log(\"Next destination (after the "+this.mnemonic_of_command+") will be to address \"+calculated_target_address_for_initial_address_"+this.incoming_address+"+\", which has offset \"+offset_from_module_start_for_target_address_for_initial_address_"+this.incoming_address+"+\" relative to the module \"+ JSON.stringify(module_containing_target_address));\n";
		retval+= spaces+"    console.log(\"Debug information on the target address: \"+JSON.stringify(DebugSymbol.fromAddress(calculated_target_address_for_initial_address_"+this.incoming_address+")));\n";
		retval+= spaces+"    //Interceptor.attach(calculated_target_address_for_initial_address_"+this.incoming_address+",function(){console.log(\"Reached target addess from computed call\")})\n";
		retval+= spaces+"}\n";
		retval+= spaces+"else\n";
		retval+= spaces+"{\n";
		retval+= spaces+"    console.log(\"calculated target address \"+calculated_target_address_for_initial_address_"+this.incoming_address+"+\" does not fall inside any of the known modules\");\n";
		retval+= spaces+"}\n";
		return retval;
	}
	
}
