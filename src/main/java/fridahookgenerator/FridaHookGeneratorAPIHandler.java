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

import java.util.ArrayList;
import java.util.stream.Collectors;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GenericAddress;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

/*
 * This class gives an API to Ghidra Scripts to invoke the Hook Generator with a list of addresses.
 * Under the hood, it invokes the SelectionHookGenerationTaskDispatcher class with the provided addresses.
 *  
 */

/*Example in python scripting:
 
 
from fridahookgenerator import AdvancedHookOptionsDialog,FridaHookGeneratorAPIHandler
apihandler=FridaHookGeneratorAPIHandler(state.getTool(),currentProgram,"0073b575,0073b5a0");
hook_str=apihandler.perform_hook_generation()


The list of addresses must be given as a string of hex (Ghidra) addresses, without 0x in the front. If their negative value is given (e.g. -0073b575), then the address is explicitly excluded from hooking.
This will spawn an AdvancedHookOptionsDialog whose options will be used to hook all the addresses.

That dialog can also be customized programmatically (in that case, it will not be shown, and also the hook will not be shown into the console, as the user will have to print it):


from fridahookgenerator import AdvancedHookOptionsDialog,FridaHookGeneratorAPIHandler

advdialog=AdvancedHookOptionsDialog(state.getTool(),currentProgram)
advdialog.isReferencestoFunctionCheckboxchecked=True
advdialog.isFunctionsReferencingFunctionCheckboxchecked=True
advdialog.IncludeCustomTextTextField.setText("console.log('currentaddr:'+this.context.pc)")
advdialog.isIncludeCustomTextcheckboxchecked=True
apihandler=FridaHookGeneratorAPIHandler(state.getTool(),currentProgram,"0073b575,0073b5a0",advdialog);
hook_str=apihandler.perform_hook_generation()
print(hook_str)




The API can also be used to generate struct offsets. For example:

from fridahookgenerator import AdvancedHookOptionsDialog,FridaHookGeneratorAPIHandler
from ghidra.program.model.data import Structure;

datatypemanager=currentProgram.getDataTypeManager()
for dt in datatypemanager.getAllDataTypes():
	if "ELF" in dt.getPathName() and isinstance(dt,Structure):  #you can put any string here
		print(dt.getPathName())
		#here recursive struct offset is done (the first True), you might not want that. The "False" means "do not output"
		apihandler=FridaHookGeneratorAPIHandler(state.getTool(),currentProgram,dt,True,False);  
		hook_str=apihandler.perform_hook_generation()
		print(hook_str)

You can also put structure paths which will be explicitly excluded from the offset generation:
		apihandler=FridaHookGeneratorAPIHandler(state.getTool(),currentProgram,dt,"/ELF/Gnu_DebugLink,/ELF/Elf64_Sym",True,False);  

 */

public class FridaHookGeneratorAPIHandler {

	private ArrayList<CodeUnit> incoming_list_of_CodeUnits;
	private ArrayList<CodeUnit> incoming_list_of_CodeUnits_to_exclude;
	private Program current_program;
	private PluginTool incoming_plugintool;
	private AdvancedHookOptionsDialog advancedhookoptionsdialog;
	private Boolean was_invoked_with_defined_advancedhookoptionsdialog;
	private Boolean was_invoked_to_generate_offsets_for_struct;
	private Boolean was_invoked_to_generate_hook_for_addresses;
	private Structure incoming_structure;
	private String[] list_of_paths_to_be_excluded;
	private Boolean should_recurse_on_struct_offset_generation;
	private Boolean should_output_on_struct_offset_generation;
	
	
	
	public FridaHookGeneratorAPIHandler(PluginTool plugintool, Program incoming_program,String list_of_addresses) {
		
		this.current_program=incoming_program;
		this.incoming_plugintool=plugintool;
		this.was_invoked_with_defined_advancedhookoptionsdialog=false;
		this.was_invoked_to_generate_offsets_for_struct=false;
		this.was_invoked_to_generate_hook_for_addresses=true;
		this.incoming_list_of_CodeUnits=extract_codeunits_from_string_of_addresses(list_of_addresses);
		this.incoming_list_of_CodeUnits_to_exclude=extract_codeunits_to_be_excluded_from_string_of_addresses(list_of_addresses);
	}
	
	public FridaHookGeneratorAPIHandler(PluginTool plugintool, Program incoming_program,String list_of_addresses, AdvancedHookOptionsDialog incoming_advancedhookoptionsdialog) {
		
		this.current_program=incoming_program;
		this.incoming_plugintool=plugintool;
		this.advancedhookoptionsdialog=incoming_advancedhookoptionsdialog;
		this.was_invoked_with_defined_advancedhookoptionsdialog=true;
		this.was_invoked_to_generate_offsets_for_struct=false;
		this.was_invoked_to_generate_hook_for_addresses=true;
		this.incoming_list_of_CodeUnits=extract_codeunits_from_string_of_addresses(list_of_addresses);
		this.incoming_list_of_CodeUnits_to_exclude=extract_codeunits_to_be_excluded_from_string_of_addresses(list_of_addresses);
	}
	
	public FridaHookGeneratorAPIHandler(PluginTool plugintool, Program incoming_program,Structure incoming_structure, Boolean should_recurse ,Boolean should_output ) {
		
		this.current_program=incoming_program;
		this.incoming_plugintool=plugintool;
		this.was_invoked_with_defined_advancedhookoptionsdialog=false;
		this.was_invoked_to_generate_offsets_for_struct=true;
		this.was_invoked_to_generate_hook_for_addresses=false;
		this.incoming_structure=incoming_structure;
		this.should_recurse_on_struct_offset_generation=should_recurse;
		this.should_output_on_struct_offset_generation=should_output;
		this.list_of_paths_to_be_excluded=new String[0];
	}
	
	public FridaHookGeneratorAPIHandler(PluginTool plugintool, Program incoming_program,Structure incoming_structure,String list_of_paths_to_be_excluded, Boolean should_recurse ,Boolean should_output ) {
		
		this.current_program=incoming_program;
		this.incoming_plugintool=plugintool;
		this.was_invoked_with_defined_advancedhookoptionsdialog=false;
		this.was_invoked_to_generate_offsets_for_struct=true;
		this.was_invoked_to_generate_hook_for_addresses=false;
		this.incoming_structure=incoming_structure;
		this.should_recurse_on_struct_offset_generation=should_recurse;
		this.should_output_on_struct_offset_generation=should_output;
		this.list_of_paths_to_be_excluded=list_of_paths_to_be_excluded.split(",");
		for (int i=0;i<this.list_of_paths_to_be_excluded.length;i++)
		{
			this.list_of_paths_to_be_excluded[i]=this.list_of_paths_to_be_excluded[i].strip();
		}
	}
	
	
	ArrayList<CodeUnit> extract_codeunits_from_string_of_addresses(String list_of_addresses)
	{
		ArrayList<CodeUnit> retval=new ArrayList<CodeUnit>(); 
		String[] str_parts=list_of_addresses.split(",");
		Listing current_program_listing=this.current_program.getListing();
		
		for (int i=0;i<str_parts.length;i++)
		{
			/*Careful: the parts have to be stripped. A list that is written with a space after the comma is the most natural thing to write, and without this the addresses that follow a space are silently dropped*/
			String current_part=str_parts[i].strip();
			if (current_part.equals(""))
			{
				continue;
			}

			if (current_part.indexOf("-")<0)  //if '-' is present, we must ignore the address
			{
				//try to decode
				long tmplong=-1;
				try {
					tmplong=Long.parseLong(current_part,16);
				}
				catch (NumberFormatException ex)
				{
					//nothing, this address will not be put into the list
					System.out.println("The address "+current_part+" could not be decoded, it will not be hooked");
				}
				if (tmplong!=-1)
				{
					//a Program may have multiple addresses spaces, but we will only take the address belonging to the first. TODO
					Address[] array_of_addresses_for_this_addr=this.current_program.parseAddress(current_part);
					if (array_of_addresses_for_this_addr.length>0 && current_program_listing.getCodeUnitAt(array_of_addresses_for_this_addr[0])!=null)
					{
						retval.add(current_program_listing.getCodeUnitAt(array_of_addresses_for_this_addr[0]));
					}
					else
					{
						System.out.println("There is no code unit at the address "+current_part+", it will not be hooked");
					}
				}
			}
		}

		return retval;
	}
	
	ArrayList<CodeUnit> extract_codeunits_to_be_excluded_from_string_of_addresses(String list_of_addresses)
	{
		ArrayList<CodeUnit> retval=new ArrayList<CodeUnit>(); 
		String[] str_parts=list_of_addresses.split(",");
		Listing current_program_listing=this.current_program.getListing();
		
		for (int i=0;i<str_parts.length;i++)
		{
			/*Careful: the parts have to be stripped here as well, for the same reason as in the function above*/
			String current_part=str_parts[i].strip();
			if (current_part.equals(""))
			{
				continue;
			}

			if (current_part.indexOf("-")==0)  //we must only put into the retval the addresses that have a negative number
			{
				//try to decode
				long tmplong=-1;
				try {
					tmplong=Long.parseLong(current_part,16);
				}
				catch (NumberFormatException ex)
				{
					//nothing, this address will not be put into the list
					System.out.println("The address "+current_part+" could not be decoded, it will not be excluded from hooking");
				}
				if (tmplong!=-1)
				{
					//a Program may have multiple addresses spaces, but we will only take the address belongng to the first. TODO
					Address[] array_of_addresses_for_this_addr=this.current_program.parseAddress(current_part.substring(1));
					if (array_of_addresses_for_this_addr.length>0 && current_program_listing.getCodeUnitAt(array_of_addresses_for_this_addr[0])!=null)
					{
						retval.add(current_program_listing.getCodeUnitAt(array_of_addresses_for_this_addr[0]));
					}
				}
			}
		}
		
		/*
		 * The distinct code units, collected straight into the kind of list that this method hands back.
		 * Careful: this used to collect with Collectors.toList() and cast the result to an ArrayList. That cast is not one the
		 * compiler complains about, because the type of the items matches, but Collectors.toList() promises nothing at all about
		 * which kind of list it returns. It happens to be an ArrayList today, so the cast happens to work, and it would start
		 * throwing on every call through the api the day somebody replaced that collector with Stream.toList() or with
		 * Collectors.toUnmodifiableList(). Asking for the list to be built as an ArrayList in the first place needs no cast.
		 */
		return retval.stream().distinct().collect(Collectors.toCollection(ArrayList::new));
	}
	
	
	
	public String perform_hook_generation()
	{
		String retval="";
		
		if (this.was_invoked_to_generate_hook_for_addresses)
		{
			SelectionHookGenerationTaskDispatcher dispatcher;
			if (this.was_invoked_with_defined_advancedhookoptionsdialog)
			{
				dispatcher= new SelectionHookGenerationTaskDispatcher(this.incoming_plugintool,this.current_program,this.incoming_list_of_CodeUnits,this.incoming_list_of_CodeUnits_to_exclude,this.advancedhookoptionsdialog);
			}
			else
			{
				dispatcher= new SelectionHookGenerationTaskDispatcher(this.incoming_plugintool,this.current_program,this.incoming_list_of_CodeUnits,this.incoming_list_of_CodeUnits_to_exclude);
			}
			
			retval= dispatcher.perform_selection_hook_action();
			
		}
		
		if (this.was_invoked_to_generate_offsets_for_struct)
		{
			StructAccessCodeGenerator structaccesscodegen=new StructAccessCodeGenerator(this.incoming_plugintool,this.current_program,this.incoming_structure,this.list_of_paths_to_be_excluded,this.should_recurse_on_struct_offset_generation,true,this.should_output_on_struct_offset_generation);
			retval=structaccesscodegen.generate_hook_str(); //will output if configured
		}
		
		
		return retval;
	}
	
	
}
