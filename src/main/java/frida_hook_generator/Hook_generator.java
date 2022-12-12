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

package frida_hook_generator;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.regex.Pattern;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class Hook_generator {

	private PluginTool incoming_plugintool;
	private Boolean isSnippet;
	private Boolean isAdvanced;
	protected String final_hook_str;
	Program incoming_program;
	Address incoming_address;
	private AdvancedHookOptionsDialog incoming_advancedhookoptionsdialog;
	private Boolean we_are_in_the_first_hook_of_the_batch;
	private Boolean we_are_in_the_final_hook_of_the_batch;
	protected Internal_structures_for_hook_generation internal_structures_for_hook_generation;
	private ConsoleService consoleService;
	private TaskMonitor incoming_monitor;
	private Boolean print_debug;
	
	private Boolean include_onEnter_in_function_hooks;
	private Boolean include_onLeave_in_function_hooks;
	private Boolean use_interceptor_attach_instead_of_replace_in_function_hooks;
	
	private Program current_program; 
	private String current_program_name;
	private String current_program_name_sanitized;
	private Listing current_program_listing;
	private Language current_program_language;
	private Address image_base;
	private Processor current_program_processor;
	private String characters_allowed_in_variable_name="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
	protected AdvancedHookOptionsDialog advancedhookoptionsdialog;
	private int maximum_number_of_reasons_to_show=0;
	
	
	
	public Hook_generator(PluginTool tool, Program incoming_program, Address incoming_address, Boolean isAdvanced, Boolean isSnippet, AdvancedHookOptionsDialog incoming_advancedhookoptionsdialog,
			TaskMonitor incoming_taskmonitor,Internal_structures_for_hook_generation incoming_internal_structures, Boolean we_are_in_the_first_hook_of_the_batch,Boolean we_are_in_the_final_hook_of_the_batch,
			ConsoleService consoleService,Boolean print_debug)
	{
		this.incoming_plugintool = tool;
		this.isSnippet = isSnippet;
		this.isAdvanced = isAdvanced;
		this.incoming_program=incoming_program;
		this.incoming_address=incoming_address;
		this.internal_structures_for_hook_generation=incoming_internal_structures;
		this.incoming_monitor=incoming_taskmonitor;
		this.incoming_advancedhookoptionsdialog=incoming_advancedhookoptionsdialog;
		this.final_hook_str="";
		this.we_are_in_the_final_hook_of_the_batch=we_are_in_the_final_hook_of_the_batch;
		this.we_are_in_the_first_hook_of_the_batch=we_are_in_the_first_hook_of_the_batch;
		this.consoleService=consoleService;
		this.print_debug=print_debug;
	}
	

	protected void do_generate_hook() {
		
		this.include_onEnter_in_function_hooks=true;
		this.include_onLeave_in_function_hooks=true;
		this.use_interceptor_attach_instead_of_replace_in_function_hooks=true;
		
		if (this.isAdvanced)
		{
			this.advancedhookoptionsdialog=this.incoming_advancedhookoptionsdialog;
		}
		
		Address addr=this.incoming_address;
		this.current_program=this.incoming_program;
		
		
		if (this.isAdvanced)
		{
			//Set up the boolean variables affecting the function hook generation
			interpret_user_custom_options_on_function_hook_generation();
		}
		
		/* Initialize some other useful things*/
		this.current_program_name = this.current_program.getName();
		Function current_function = this.current_program.getFunctionManager().getFunctionContaining(addr);
		this.current_program_listing = this.current_program.getListing();
		this.current_program_name_sanitized = this.current_program_name.replaceAll("[^"+this.characters_allowed_in_variable_name+"]", "_");
		this.image_base = this.current_program.getImageBase();
		this.current_program_language = this.current_program.getLanguage();
		this.current_program_processor = this.current_program_language.getProcessor();


		//Begin creating the hook
		String hook_str="";
		
		//Now, in case of Advanced Options, make sure to update the isSnippet variable
		if (this.isAdvanced)
		{
			if (this.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked)
			{
				this.isSnippet=false;
			}
			else
			{
				this.isSnippet=true;
			}
		}
		
		
		//Create the prologue
		if (!this.isSnippet && this.we_are_in_the_first_hook_of_the_batch)
		{
			hook_str+=generate_prologue_for_address(addr,true);
		}
		
		//handle the simple right click case
		if (!this.isAdvanced)
		{
			handle_simple_right_click_hook_generation(addr,true);
		}
		//handle all Advanced cases
		if (this.isAdvanced)
		{
			handle_advanced_hook_generation(addr,false);
		}
		
		if (this.we_are_in_the_final_hook_of_the_batch && !this.incoming_monitor.isCancelled())
		{
			if (this.isAdvanced && this.advancedhookoptionsdialog.isOutputReasonForHookGenCheckboxchecked)
			{
				backpatch_reasons_for_advanced_hook_generation(); //this will update the reasons in the individual hooks
			}
			if (this.isAdvanced && !this.incoming_monitor.isCancelled() && is_there_a_chance_that_some_hooks_generated_in_the_current_batch_require_code_that_is_later_added_in_the_hook())
			{
				backpatch_hooks_that_need_code_to_be_added_at_a_later_stage(); //this will update the hooks that may need further additions to their code. Note: This should happen in any case that there is a chance that one address had such a hook, as placeholders will have been put. In other words, if any of the related advanced options is selected, call this function
			}
			if (!this.incoming_monitor.isCancelled())
			{
				hook_str=hook_str.concat(gather_all_generated_hooks());
			}
		}
		
		

		//Now, the epilogue
		if (!this.isSnippet && this.we_are_in_the_final_hook_of_the_batch && !this.incoming_monitor.isCancelled())
		{
			hook_str+=generate_epilogue_for_address(addr,true);
		}
		
		handle_output(hook_str);
		
	
	}
	
	
	protected String generate_epilogue_for_address(Address addr, Boolean print_debug) {
		
		String hook_str="";
		
		if (!this.isAdvanced || (this.isAdvanced && !this.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked) || (this.isAdvanced && this.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==0))
		{
			//default method
			hook_str+="      \n";
			hook_str+="      Interceptor.flush();\n"
					+ "      console.log(\"Registered interceptors.\");\n"
					+ "    }, 2000);//milliseconds\n"
					+ "}\n"
					+ "start_timer_for_intercept();\n";
		}
		if (this.isAdvanced && this.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==1 ||
				this.isAdvanced && this.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==2 )
		{
			//dlopen() or LoadLibrary() method
			hook_str+="      \n"
					+ "      Interceptor.flush();\n"
					+ "      console.log(\"Registered interceptors.\");\n"
					+ "}\n";
		}
		
		return hook_str;
				
	}
	
	
	protected String generate_prologue_for_address(Address addr, Boolean print_debug) {
		
		String hook_str="";
		
		if (!this.isAdvanced || (this.isAdvanced && !this.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked) || (this.isAdvanced && this.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==0))
		{
			//default method
			hook_str+="var module_name_"+this.current_program_name_sanitized+"='"+this.current_program_name+"';\n";
			hook_str+="\n";
			hook_str+="function start_timer_for_intercept() {\n"
					+ "  setTimeout(\n"
					+ "    function() {\n"
					+ "      console.log(\"Registering interceptors...\");\n";
			hook_str+="      \n";
			hook_str+="      \n";
		}
		if (this.isAdvanced && this.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==1)
		{
			//dlopen() method
			hook_str+="var module_name_"+this.current_program_name_sanitized+"='"+this.current_program_name+"';\n";
			hook_str+="\n";
			hook_str+="function extract_libname_from_dlopen_arg(dlopen_arg)\n"
					+ "{\n"
					+ "    if (dlopen_arg!==null && dlopen_arg.indexOf(\"/\")>=0)\n"
					+ "    {\n"
					+ "        var array_of_subdirs=dlopen_arg.split(\"/\");\n"
					+ "        return array_of_subdirs[array_of_subdirs.length-1];\n"
					+ "    }\n"
					+ "    else\n"
					+ "    {\n"
					+ "        return dlopen_arg;\n"
					+ "    }\n"
					+ "}\n"
					+ "\n"
					+ "function do_the_dlopen_interception(incoming_export)\n"
					+ "{\n"
					+ "    Interceptor.attach(incoming_export.address, {\n"
					+ "        onEnter: function(args) {\n"
					+ "            console.log(\"DLOPEN: Entered dlopen related function: \"+incoming_export.name + \", lib to load:\"+args[0].readCString());\n"
					+ "            this.libname=args[0].readCString();\n"
					+ "        },\n"
					+ "        onLeave: function(retval) {\n"
					+ "            console.log(\"DLOPEN: Exited dlopen related function:\"+incoming_export.name+\" ,retval:\"+retval);\n"
					+ "            if (extract_libname_from_dlopen_arg(this.libname)==module_name_"+this.current_program_name_sanitized+")\n"
					+ "            {\n"
					+ "                register_interceptors();\n"
					+ "            }\n"
					+ "        }\n"
					+ "    });\n"
					+ "}\n"
					+ "\n"
					+ "var process_modules = Process.enumerateModules();\n"
					+ "var we_have_encountered_at_least_one_dlopen=false;\n"
					+ "var we_encountered_the_lib_in_the_initial_pass_of_the_loaded_modules=false;\n"
					+ "for(var i=0;i<process_modules.length;i++){\n"
					+ "\n"
					+ "    if (process_modules[i].name==module_name_"+this.current_program_name_sanitized+")\n"
					+ "    {\n"
					+ "        console.log(\"The module to register interceptors in, was found already loaded\");\n"
					+ "        we_encountered_the_lib_in_the_initial_pass_of_the_loaded_modules=true;\n"
					+ "        register_interceptors();\n"
					+ "        break;\n"
					+ "    }\n"
					+ "    var exports = process_modules[i].enumerateExports();\n"
					+ "    for(var j=0;j<exports.length;j++)\n"
					+ "    {\n"
					+ "        //if (exports[j].name.indexOf(\"dlopen\")>=0) //there may be more than one dlopen related functions, like __libc_dlopen_mode()\n"
					+ "        if (exports[j].name==\"dlopen\")\n"
					+ "        {\n"
					+ "            console.log(process_modules[i].name);\n"
					+ "            console.log(JSON.stringify(exports[j]));\n"
					+ "            do_the_dlopen_interception(exports[j]);\n"
					+ "            we_have_encountered_at_least_one_dlopen=true;\n"
					+ "        }\n"
					+ "    }\n"
					+ "}\n"
					+ "if (!we_encountered_the_lib_in_the_initial_pass_of_the_loaded_modules && !we_have_encountered_at_least_one_dlopen)\n"
					+ "{\n"
					+ "    console.log(\"DLOPEN: No dlopen found, exiting the frida script...\")\n"
					+ "    throw '';\n"
					+ "}\n"
					+ "\n"
					+ "\n"
					+ "function register_interceptors()\n"
					+ "{\n"
					+ "      console.log(\"Registering interceptors...\");\n"
					+ "      \n\n";
			
		}
		if (this.isAdvanced && this.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==2)
		{
			//LoadLibrary() method
			hook_str+="var module_name_"+this.current_program_name_sanitized+"='"+this.current_program_name+"';\n";
			hook_str+="\n";
			hook_str+="function extract_libname_from_loadlibrary_arg(loadlibrary_arg)\n"
					+ "{\n"
					+ "    if (loadlibrary_arg!==null && loadlibrary_arg.indexOf(\"\\\\\")>=0)\n"
					+ "    {\n"
					+ "        var array_of_subdirs=loadlibrary_arg.split(\"\\\\\");\n"
					+ "        return array_of_subdirs[array_of_subdirs.length-1]; \n"
					+ "    }\n"
					+ "    else\n"
					+ "    {\n"
					+ "        return loadlibrary_arg;\n"
					+ "    }\n"
					+ "}\n"
					+ "\n"
					+ "function do_the_loadlibrary_interception(incoming_export)\n"
					+ "{\n"
					+ "    Interceptor.attach(incoming_export.address, {\n"
					+ "        onEnter: function(args) {\n"
					+ "            if (incoming_export.name.charAt(incoming_export.name.length - 1)==\"A\")\n"
					+ "            {\n"
					+ "                this.libname=args[0].readAnsiString();\n"
					+ "            }\n"
					+ "            else\n"
					+ "            {\n"
					+ "                this.libname=args[0].readUtf16String();\n"
					+ "            }\n"
					+ "            console.log(\"LOADLIBRARY: Entered LoadLibrary related function: \"+incoming_export.name + \", lib to load:\"+this.libname);\n"
					+ "\n"
					+ "        },\n"
					+ "        onLeave: function(retval) {\n"
					+ "            console.log(\"LOADLIBRARY: Exited LoadLibrary related function:\"+incoming_export.name+\" ,retval:\"+retval);\n"
					+ "            if (extract_libname_from_loadlibrary_arg(this.libname).toLowerCase()==module_name_"+this.current_program_name_sanitized+".toLowerCase() || (extract_libname_from_loadlibrary_arg(this.libname)+\".dll\").toLowerCase()==module_name_"+this.current_program_name_sanitized+".toLowerCase())\n"
					+ "            {\n"
					+ "                register_interceptors();\n"
					+ "            }\n"
					+ "        }\n"
					+ "    });\n"
					+ "}\n"
					+ "\n"
					+ "var process_modules = Process.enumerateModules();\n"
					+ "var we_have_encountered_at_least_one_loadlibrary=false;\n"
					+ "var we_encountered_the_lib_in_the_initial_pass_of_the_loaded_modules=false;\n"
					+ "for(var i=0;i<process_modules.length;i++){\n"
					+ "\n"
					+ "    if (process_modules[i].name.toLowerCase()==module_name_"+this.current_program_name_sanitized+".toLowerCase() || (process_modules[i].name+\".dll\").toLowerCase()==module_name_"+this.current_program_name_sanitized+".toLowerCase() )\n"
					+ "    {\n"
					+ "        console.log(\"Encountered the module already loaded\");\n"
					+ "        we_encountered_the_lib_in_the_initial_pass_of_the_loaded_modules=true;\n"
					+ "        register_interceptors();\n"
					+ "        break;\n"
					+ "    }\n"
					+ "    var exports = process_modules[i].enumerateExports();\n"
					+ "    for(var j=0;j<exports.length;j++)\n"
					+ "    {\n"
					+ "        //if (exports[j].name==\"LoadLibrary\")\n"
					+ "        if (exports[j].name.indexOf(\"LoadLibrary\")>=0) //there may be more than one LoadLibrary related functions, like LoadLibraryEx(), LoadLibraryExW(), LoadLibraryExA() ....\n"
					+ "        {\n"
					+ "            console.log(process_modules[i].name);\n"
					+ "            console.log(JSON.stringify(exports[j]));\n"
					+ "            do_the_loadlibrary_interception(exports[j]);\n"
					+ "            we_have_encountered_at_least_one_loadlibrary=true;\n"
					+ "        }\n"
					+ "    }\n"
					+ "}\n"
					+ "if (!we_encountered_the_lib_in_the_initial_pass_of_the_loaded_modules && !we_have_encountered_at_least_one_loadlibrary)\n"
					+ "{\n"
					+ "    console.log(\"LOADLIBRARY: No LoadLibrary found, exiting the frida script...\")\n"
					+ "    throw '';\n"
					+ "}\n"
					+ "\n"
					+ "\n"
					+ "function register_interceptors()\n"
					+ "{\n"
					+ "      console.log(\"Registering interceptors...\");\n"
					+ "      \n\n";
		}
		return hook_str;
		
	}
	

	protected void handle_output(String hook_str)
	{
		if (this.incoming_monitor!=null && this.incoming_monitor.isCancelled() )
		{
			//This is the case where the user has manually cancelled
			hook_str="// User has cancelled\n";
		}
		this.final_hook_str=hook_str;  //Simply set the this.final_hook_str, the caller classes will take care of outputting to the user
	}
	
	
	
	
	
	
	protected void handle_simple_right_click_hook_generation(Address addr, Boolean print_debug)
	{
		generate_snippet_hook_for_address(addr,print_debug,"Simple Right Click");
	}
	
	
	
	
	/* This is a big and complex function, handling all sub-cases for the advanced hook generation*/
	protected void handle_advanced_hook_generation(Address addr, Boolean print_debug)
	{
		Function current_function = this.current_program.getFunctionManager().getFunctionContaining(addr);

		if (this.incoming_monitor.isCancelled()) {return ;} //check for cancellation by the user
		this.incoming_monitor.setMessage("Generating Hooks...");
		
		
		/*References to address*/
		if (this.advancedhookoptionsdialog.isReferencestoAddressCheckBoxchecked || this.advancedhookoptionsdialog.isFunctionsReferencingAddressCheckBoxchecked)
		{
			CodeUnit current_codeunit=this.current_program_listing.getCodeUnitAt(addr);
			Instruction current_instruction=this.current_program_listing.getInstructionAt(addr); //The current address may not be in code, careful
			if (current_codeunit!=null)
			{
				ReferenceIterator ref_iter= current_codeunit.getReferenceIteratorTo();
				while(ref_iter.hasNext())
				{
					Reference ref = ref_iter.next();
					Address newaddr=ref.getFromAddress();
					if (this.advancedhookoptionsdialog.isReferencestoAddressCheckBoxchecked)
					{
						generate_snippet_hook_for_address(newaddr,true,"Address referencing address "+addr+" , referenceType:"+ref.getReferenceType());
					}
					if (this.advancedhookoptionsdialog.isFunctionsReferencingAddressCheckBoxchecked)
					{
						Function newfun=this.current_program.getFunctionManager().getFunctionContaining(newaddr);
						if (newfun!=null)
						{
							generate_snippet_hook_for_address(newfun.getEntryPoint(),true,"Function containing address "+newaddr+" that references to initial address "+addr+" through referenceType:"+ref.getReferenceType());
					
						}	
					}
				}					
			}
		}
		
		if (this.incoming_monitor.isCancelled()) { return;} //check for cancellation by the user

		
		/*References to function*/
		if (this.advancedhookoptionsdialog.isReferencestoFunctionCheckboxchecked && current_function!=null)
		{
			Instruction instruction_of_current_function_start=this.current_program_listing.getInstructionAt(current_function.getEntryPoint());
		
			if (instruction_of_current_function_start!=null)
			{
				ReferenceIterator ref_iter= instruction_of_current_function_start.getReferenceIteratorTo();
				while(ref_iter.hasNext())
				{
					Reference ref = ref_iter.next();
					Address newaddr=ref.getFromAddress();
					generate_snippet_hook_for_address(newaddr,true,"Address referencing function at "+current_function.getEntryPoint()+" named "+current_function.getName(true).replace("\"", "_")+" containing address "+addr+", through referenceType:"+ref.getReferenceType());
				}
			}
			
		}
		
		if (this.incoming_monitor.isCancelled()) { return;} //check for cancellation by the user
	
		/*Incoming references, for a certain depth*/
		if (this.advancedhookoptionsdialog.isFunctionsReferencingFunctionCheckboxchecked && current_function!=null)
		{
			int i;
			int j;
			int depth=Integer.parseInt(this.advancedhookoptionsdialog.InFunctionReferenceDepthcomboBox.getItemAt(this.advancedhookoptionsdialog.InFunctionReferenceDepthcomboBox.getSelectedIndex()));
			
			/*
			 * Complex data type, the external ArrayList holds items for each depth level, and the internal ArrayList contains Functions for a specific depth, accompanied by helper values (all in a Container) . This entire data structure serves the purpose of keeping track of the reference arrows (who has called who), in order to follow them backwards
			 * At position all_depths_arraylists_of_function_references.get(i).get(j), the j'th caller Function for depth 'i' is held. (The j'th as returned by a set iterator, not necessarily being at the j'th position in the code).
			 */
			ArrayList<ArrayList<Container_for_function_references>> all_depths_arraylists_of_function_references=new ArrayList<ArrayList<Container_for_function_references>>();

			//initially for level 0
			ArrayList<Container_for_function_references> arraylist_for_level_i=new ArrayList<Container_for_function_references>();
			arraylist_for_level_i.add(new Container_for_function_references(current_function,-1,-1,0));
			all_depths_arraylists_of_function_references.add((ArrayList<Container_for_function_references>) arraylist_for_level_i.clone());
			

			for (i=1;i<=depth;i++)
			{
				this.incoming_monitor.setMessage("Incoming references, level "+i);
				
				arraylist_for_level_i=handle_incoming_references_for_one_depth_level((ArrayList<Container_for_function_references>) arraylist_for_level_i.clone(),i);
				all_depths_arraylists_of_function_references.add((ArrayList<Container_for_function_references>) arraylist_for_level_i.clone());
				for (j=0;j<arraylist_for_level_i.size();j++)
				{
					Function newfun=arraylist_for_level_i.get(j).fun;
					String reference_path_string=get_incoming_reference_path_string(all_depths_arraylists_of_function_references,i,j);
					generate_snippet_hook_for_address(newfun.getEntryPoint(),false,"Incoming function call reference from function at "+newfun.getEntryPoint()+" named "+newfun.getName(true).replace("\"", "_")+", to final current function "+current_function.getName(true).replace("\"", "_")+" containing address "+addr+", after call depth="+i+", using call path:"+reference_path_string);
				
					if (j%100==0 && this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
				}
				if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
			}
			
		}
		
		/*Outgoing references, for a certain depth*/
		if (this.advancedhookoptionsdialog.isOutReferencesfromFunctionCheckBoxchecked && current_function!=null)
		{
			int i;
			int j;
			int depth=Integer.parseInt(this.advancedhookoptionsdialog.OutFunctionReferenceDepthcomboBox.getItemAt(this.advancedhookoptionsdialog.OutFunctionReferenceDepthcomboBox.getSelectedIndex()));
			
			/*
			 * Complex data type, the external ArrayList holds items for each depth level, and the internal ArrayList contains Functions for a specific depth, accompanied by helper values (all in a Container) . This entire data structure serves the purpose of keeping track of the reference arrows (who has called who), in order to follow them backwards
			 * At position all_depths_arraylists_of_function_references.get(i).get(j), the j'th called Function for depth 'i' is held. (The j'th as returned by a set iterator, not necessarily being at the j'th position in the code).
			 */				
			ArrayList<ArrayList<Container_for_function_references>> all_depths_arraylists_of_function_references=new ArrayList<ArrayList<Container_for_function_references>>();

			//initially for level 0
			ArrayList<Container_for_function_references> arraylist_for_level_i=new ArrayList<Container_for_function_references>();
			arraylist_for_level_i.add(new Container_for_function_references(current_function,-1,-1,0));
			all_depths_arraylists_of_function_references.add((ArrayList<Container_for_function_references>) arraylist_for_level_i.clone());
							
			for (i=1;i<=depth;i++)
			{
				this.incoming_monitor.setMessage("Outgoing calls, level "+i);
				arraylist_for_level_i=handle_outgoing_references_for_one_depth_level((ArrayList<Container_for_function_references>) arraylist_for_level_i.clone(),i);
				all_depths_arraylists_of_function_references.add((ArrayList<Container_for_function_references>) arraylist_for_level_i.clone());
				for (j=0;j<arraylist_for_level_i.size();j++)
				{
					Function newfun=arraylist_for_level_i.get(j).fun;
					String reference_path_string=get_outgoing_reference_path_string(all_depths_arraylists_of_function_references,i,j);
					generate_snippet_hook_for_address(newfun.getEntryPoint(),false,"Outgoing function call reference to function at "+newfun.getEntryPoint()+" named "+newfun.getName(true).replace("\"", "_")+", from initial current function "+current_function.getName(true).replace("\"", "_")+" containing address "+addr+", after call depth="+i+", using call path:"+reference_path_string);
					
					if (j%100==0 && this.incoming_monitor.isCancelled()) { return;} //check for cancellation by the user
				}
				if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
			}
			
		}
		
		if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
		
		
		if (this.advancedhookoptionsdialog.isOutReferencesfromAddressCheckBoxchecked)
		{
			CodeUnit current_codeunit=this.current_program_listing.getCodeUnitAt(addr);
			Instruction current_instruction=this.current_program_listing.getInstructionAt(addr); //The current address may not be in code, careful
			if (current_codeunit!=null)
			{
				Reference[] references= current_codeunit.getReferencesFrom();
				for (int i=0;i<references.length;i++)
				{
					Reference ref = references[i];
					Address newaddr=ref.getToAddress();
					generate_snippet_hook_for_address(newaddr,true,"Address referenced from address "+addr+" , referenceType:"+ref.getReferenceType());
				}					
			}
		}
		
		if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
		
		if (this.advancedhookoptionsdialog.isOutDynamicCallReferencesfromFunctionCheckBoxchecked && current_function!=null && is_there_a_chance_that_some_hooks_generated_in_the_current_batch_require_code_that_is_later_added_in_the_hook())
		{
			this.incoming_monitor.setMessage("Dynamic calls for function...");
			AddressIterator all_addresses_in_this_function=current_function.getBody().getAddresses(true);
			int addresses_processed=0;
			
			while (all_addresses_in_this_function.hasNext())
			{
				Address newaddr=all_addresses_in_this_function.next();
				Instruction newinstr=this.current_program_listing.getInstructionAt(newaddr);
				String reason_for_hook="Address "+newaddr+" containing a dynamic (computed) call/jump";
				if (newinstr!=null && does_the_current_instruction_definitely_need_hook_code_to_also_be_added_later(newinstr,reason_for_hook))
				{	
					generate_snippet_hook_for_address(newaddr,true,reason_for_hook);		//Careful: This particular reason is used to check if internal data structures should be updated. If changed, update the  update_internal_data_structures()/does_the_current_instruction_definitely_need_hook_code_to_also_be_added_later() function		
				}
				
				if (addresses_processed%200==0 && this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
				addresses_processed++;
			}

		}
		
		if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
		
		
		/*Hook this address checkbox*/
		if (this.advancedhookoptionsdialog.isHookThisAddressCheckBoxchecked)
		{
			this.incoming_monitor.setMessage("Hooking this address...");
			
			generate_snippet_hook_for_address(addr,true,"Asked to hook the current (selected) address, which was used to spawn the dialog");
		}
		
		if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user

		
		/* Range hooking, for addresses */
		// TODO: see if this can be done faster, perhaps by iterating over instructions only. Careful with the function endings
		if (this.advancedhookoptionsdialog.isRangeAddressesCheckBoxchecked && this.advancedhookoptionsdialog.RangeAddressesNum>0)
		{
			long max_address=this.current_program.getMaxAddress().getOffset();  //this does not work, keeping it here for future reference 
			long initial_addr_offset=addr.getOffset();
			long curraddr_offset=initial_addr_offset;
			int num_of_addresses_advanced=0;
			int num_of_instructions_advanced=0;
			int num_of_functions_advanced=0;
			int number_of_times_iterated=0;
			
			if (print_debug)
			{
				System.out.println("RangeAddressesNum: "+this.advancedhookoptionsdialog.RangeAddressesNum);
			}

			this.incoming_monitor.setMessage("Range for addresses...");
			
			CodeUnitIterator code_unit_iterator=this.current_program_listing.getCodeUnits(addr, true);

			if (code_unit_iterator!=null)
			{
				while (code_unit_iterator.hasNext())
				{
					CodeUnit newcodeunit=code_unit_iterator.next();
					Address newaddr=newcodeunit.getAddress();
					Boolean we_are_at_the_first_byte_of_an_instruction=false;
					Boolean we_have_reached_the_maxaddress_of_a_function=false;
					number_of_times_iterated++;
					
					/*
					 * A function may have its MaxAddress on something other than an instruction.
					 * Also, very important: The MaxAddress seems to be the last byte of the last code unit, not the start of the last code unit
					 */
					Function newfun = this.current_program.getFunctionManager().getFunctionContaining(newaddr);
					if (newfun!=null &&  this.current_program_listing.getCodeUnitContaining(newfun.getBody().getMaxAddress()).equals(newcodeunit)) //function has ended
					{
						we_have_reached_the_maxaddress_of_a_function=true;
					}
					
					Instruction newinstr=current_program_listing.getInstructionAt(newaddr);	
					if (newinstr!=null) 
					{
						we_are_at_the_first_byte_of_an_instruction=true;
					}
					

					
					if (we_have_reached_the_maxaddress_of_a_function)
					{
						//increase the function counter
						num_of_functions_advanced++;
					}
					if (we_are_at_the_first_byte_of_an_instruction)
					{
						//Increase the instruction counter
						num_of_instructions_advanced++;
					}
					
					//Increase the address counters
					curraddr_offset=newaddr.getOffset()-initial_addr_offset;
					num_of_addresses_advanced=(int) (newaddr.getOffset()-initial_addr_offset);
					
					
					/* Careful: if we have exceeded the allowed addresses, break. Else, continue and hook.*/
					if (this.advancedhookoptionsdialog.RangeAddressesRadioButtonAddr.isSelected() && num_of_addresses_advanced>this.advancedhookoptionsdialog.RangeAddressesNum)
					{
						break;
					}
					
					if (we_are_at_the_first_byte_of_an_instruction)
					{
						//We can only hook instructions at their first byte
						generate_snippet_hook_for_address(newaddr,false,"Address hook in range of initial address "+addr+". Offset from that: "+num_of_addresses_advanced+" addresses, "+num_of_instructions_advanced+" instructions, "+num_of_functions_advanced+" functions.");
					}
					
					/*Now, the check is for >= , as both the instructions and the functions will always increase one by one*/
					if (this.advancedhookoptionsdialog.RangeAddressesRadioButtonFun.isSelected() && num_of_functions_advanced>=this.advancedhookoptionsdialog.RangeAddressesNum)
					{
						break;
					}
					if (this.advancedhookoptionsdialog.RangeAddressesRadioButtonInstr.isSelected() && num_of_instructions_advanced>=this.advancedhookoptionsdialog.RangeAddressesNum)
					{
						break;
					}

					if (number_of_times_iterated%100==0 && this.incoming_monitor.isCancelled()) { return;} //check for cancellation by the user
					if (number_of_times_iterated%2000==0) 
					{
						//update the "Generating hooks..." dialog
						if (this.advancedhookoptionsdialog.RangeAddressesRadioButtonAddr.isSelected()) {this.incoming_monitor.setMessage("Range for addresses "+num_of_addresses_advanced+"...");}
						if (this.advancedhookoptionsdialog.RangeAddressesRadioButtonInstr.isSelected()) {this.incoming_monitor.setMessage("Range for addresses "+num_of_instructions_advanced+"...");}
						if (this.advancedhookoptionsdialog.RangeAddressesRadioButtonFun.isSelected()) {this.incoming_monitor.setMessage("Range for addresses "+num_of_functions_advanced+"...");}
					}
				}
			}
		}
		
		
		/* Range hooking, for functions, only forward */
		if (this.advancedhookoptionsdialog.isRangeFunctionsCheckBoxchecked && this.advancedhookoptionsdialog.RangeFunctionsNum>0 && !this.advancedhookoptionsdialog.RangeFunctionsRadioButtonFunBackwards.isSelected())
		{
			//get all functions starting from this address
			FunctionIterator fun_iter=this.current_program_listing.getFunctions(addr, true);
			long initial_addr_offset=addr.getOffset();
			long curraddr_offset=initial_addr_offset;
			int num_of_addresses_advanced=0;
			//instructions will not be used as a counter, is there any way of using them, without iterating over all of the instructions? In other words, to get the number of instructions inside a function, without iterating over all of them.
			//int num_of_instructions_advanced=0;
			int num_of_functions_advanced=0;
			long offset_of_new_fun_end;
			long offset_of_new_fun_start;
			Boolean we_are_done_for_RangeFunctions=false;
			
			this.incoming_monitor.setMessage("Range for functions...");
			
			//if we are inside a function, we want to hook that one
			Function newfun = this.current_program.getFunctionManager().getFunctionContaining(addr);
			
			if (newfun!=null)
			{
				generate_snippet_hook_for_address(newfun.getEntryPoint(),false,"Function hook in range of initial address "+addr+". Offset from that: "+num_of_addresses_advanced+" addresses, "+num_of_functions_advanced+" functions.");
				num_of_functions_advanced++; //in this case, 1 function means -> hook the present one
				if (newfun.getEntryPoint().equals(addr))
				{
					//consume the first of the iterator if we are at the start of the first function.
					if (fun_iter.hasNext()) {fun_iter.next();};
				}
			}
			
			while (!we_are_done_for_RangeFunctions && fun_iter.hasNext())
			{
				newfun=fun_iter.next();
				offset_of_new_fun_end=newfun.getBody().getMaxAddress().getOffset();
				offset_of_new_fun_start=newfun.getEntryPoint().getOffset();
				num_of_addresses_advanced=(int) (offset_of_new_fun_start-initial_addr_offset);
				num_of_functions_advanced++;
				if (this.advancedhookoptionsdialog.RangeFunctionsRadioButtonAddr.isSelected() && num_of_addresses_advanced>this.advancedhookoptionsdialog.RangeFunctionsNum) 
				{
					we_are_done_for_RangeFunctions=true;
					break;
				}
				if (this.advancedhookoptionsdialog.RangeFunctionsRadioButtonFun.isSelected() && num_of_functions_advanced>this.advancedhookoptionsdialog.RangeFunctionsNum)
				{
					we_are_done_for_RangeFunctions=true;
					break;
				}
				generate_snippet_hook_for_address(newfun.getEntryPoint(),false,"Function hook in range of initial address "+addr+". Offset from that: "+num_of_addresses_advanced+" addresses, "+num_of_functions_advanced+" functions.");
			
				if (num_of_functions_advanced%100==0 && this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
				if (num_of_functions_advanced%1000==0) {this.incoming_monitor.setMessage("Range for functions "+num_of_functions_advanced+"...");}
			}

		}
		
		if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user

		
		/* Range hooking, for functions, only backwards */
		if (this.advancedhookoptionsdialog.isRangeFunctionsCheckBoxchecked && this.advancedhookoptionsdialog.RangeFunctionsNum>0 && this.advancedhookoptionsdialog.RangeFunctionsRadioButtonFunBackwards.isSelected())
		{
			//get all functions starting from this address, going backwards
			FunctionIterator fun_iter=this.current_program_listing.getFunctions(addr, false);
			long initial_addr_offset=addr.getOffset();
			long curraddr_offset=initial_addr_offset;
			int num_of_addresses_advanced=0;
			int num_of_functions_advanced=0;
			long offset_of_new_fun_end;
			long offset_of_new_fun_start;
			Boolean we_are_done_for_RangeFunctions=false;
			
			this.incoming_monitor.setMessage("Range for functions (backwards)...");
			
			//if we are inside a function, we want to hook that one
			Function newfun = this.current_program.getFunctionManager().getFunctionContaining(addr);
			
			if (newfun!=null)
			{
				generate_snippet_hook_for_address(newfun.getEntryPoint(),false,"Function hook in range of initial address "+addr+" going backwards. Offset from that: "+num_of_addresses_advanced+" addresses, "+num_of_functions_advanced+" functions.");
				num_of_functions_advanced++; //in this case, 1 function means -> hook the present one
				//consume the first of the iterator, since when we are in a function, the first of the backwards iterator will give the function itself
				if (fun_iter.hasNext()) {fun_iter.next();};
			}
			
			while (!we_are_done_for_RangeFunctions && fun_iter.hasNext())
			{
				newfun=fun_iter.next();
				offset_of_new_fun_end=newfun.getBody().getMaxAddress().getOffset();
				offset_of_new_fun_start=newfun.getEntryPoint().getOffset();
				num_of_addresses_advanced=(int) (initial_addr_offset-offset_of_new_fun_start);
				num_of_functions_advanced++;

				if ( num_of_functions_advanced>this.advancedhookoptionsdialog.RangeFunctionsNum)
				{
					we_are_done_for_RangeFunctions=true;
					break;
				}
				generate_snippet_hook_for_address(newfun.getEntryPoint(),false,"Function hook in range of initial address "+addr+" going backwards. Offset from that: "+num_of_addresses_advanced+" addresses, "+num_of_functions_advanced+" functions.");
			
				if (num_of_functions_advanced%100==0 && this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
				if (num_of_functions_advanced%1000==0) {this.incoming_monitor.setMessage("Range for functions (backwards) "+num_of_functions_advanced+"...");}
			}
		}
	
		if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user

		
		/* Function name regex hooking */
		if (this.advancedhookoptionsdialog.isFunctionRegexCheckBoxchecked)
		{
			String regex_for_fun_name=this.advancedhookoptionsdialog.FunctionRegexTextField.getText();
			Pattern pattern= Pattern.compile(regex_for_fun_name,Pattern.CASE_INSENSITIVE);
			FunctionIterator fun_iter=this.current_program_listing.getFunctions(true);
			int num_of_functions_processed=0;
			
			if (this.incoming_monitor.isCancelled()) {return;}
			this.incoming_monitor.setMessage("Function hooking by regex....");
			
			while(fun_iter!=null && fun_iter.hasNext())
			{
				Function newfun=fun_iter.next();
				num_of_functions_processed++;
				String name_of_newfun=newfun.getName(true).replace("\"", "_");
				if (pattern.matcher(name_of_newfun).matches())
				{
					generate_snippet_hook_for_address(newfun.getEntryPoint(),false,"Function hook to function "+name_of_newfun+" due to matching regex:"+regex_for_fun_name);
				}
				if (num_of_functions_processed%100==0 && this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
			}
			
		
		}

	}
	
	
		
	
	protected ArrayList<Container_for_function_references> handle_outgoing_references_for_one_depth_level(ArrayList<Container_for_function_references> incoming_functions_from_previous_level,int current_depth)
	{
		int i;
		ArrayList<Container_for_function_references> retval=new ArrayList<Container_for_function_references>();
		for (i=0;i<incoming_functions_from_previous_level.size();i++)
		{
			Function newfun=incoming_functions_from_previous_level.get(i).fun;
			Set<Function> called_functions=newfun.getCalledFunctions(null);
			if (called_functions!=null)
			{
				Iterator<Function> iter=called_functions.iterator();
				while (iter.hasNext())
				{
					Function newfun2=iter.next();
					Container_for_function_references newcontainer=new Container_for_function_references(newfun2,i,-1,current_depth);
					retval.add(newcontainer);
					if (incoming_functions_from_previous_level.get(i).first_index_of_dest_at_next_depth==-1)
					{
						incoming_functions_from_previous_level.get(i).first_index_of_dest_at_next_depth=retval.size()-1; //fix the container's index at the previous level if it is not set
					}
				}
			}
			
		}
		return retval;
	}
	
	
	//Try to move backwards in the data structure to see the reference path
	String get_outgoing_reference_path_string(ArrayList<ArrayList<Container_for_function_references>> all_depths_arraylists_of_function_references,int depth,int index_of_container_for_that_depth)
	{
		String retval="";
		
		int tmpdepth=depth;
		int index_of_caller_in_previous_level=index_of_container_for_that_depth;
		while(tmpdepth>=0)
		{
			Container_for_function_references tmpcontainer=all_depths_arraylists_of_function_references.get(tmpdepth).get(index_of_caller_in_previous_level);
			Function tmpfun=tmpcontainer.fun;
			index_of_caller_in_previous_level=tmpcontainer.index_of_source_at_previous_depth;
			if (tmpdepth>0)
			{
				retval="->".concat(tmpfun.getName(true).replace("\"", "_")).concat(retval);
			}
			else
			{
				retval=tmpfun.getName(true).replace("\"", "_").concat(retval);
			}
			tmpdepth--;
		}
		
		return retval;
	}
	
	

	protected ArrayList<Container_for_function_references> handle_incoming_references_for_one_depth_level(ArrayList<Container_for_function_references> called_functions_from_previous_level,int current_depth)
	{
		int i;
		ArrayList<Container_for_function_references> retval=new ArrayList<Container_for_function_references>();
		for (i=0;i<called_functions_from_previous_level.size();i++)
		{
			Function newfun=called_functions_from_previous_level.get(i).fun;
			Set<Function> calling_functions=newfun.getCallingFunctions(null);
			if (calling_functions!=null)
			{
				Iterator<Function> iter=calling_functions.iterator();
				while (iter.hasNext())
				{
					Function newfun2=iter.next();
					Container_for_function_references newcontainer=new Container_for_function_references(newfun2,i,-1,current_depth);
					retval.add(newcontainer);
					if (called_functions_from_previous_level.get(i).first_index_of_dest_at_next_depth==-1)
					{
						called_functions_from_previous_level.get(i).first_index_of_dest_at_next_depth=retval.size()-1; //fix the container's index at the previous level if it is not set
					}
				}
			}
			
		}
		return retval;
	}
	
	
	
	
	
	protected String gather_all_generated_hooks()
	{
		String hook_str="";
		StringBuffer sb=new StringBuffer(10000000); //Much faster than simple string concatenation when doing it for many strings
		
		if (this.incoming_monitor.isCancelled()) {return "";} //check for cancellation by the user)
		this.incoming_monitor.setMessage("Gathering all generated hooks in one...");
		
		int i;
		for (i=0;i<this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch;i++)
		{
			sb.append(this.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.get(i));
			if (this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.containsKey(i))
			{
				sb.append(this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.get(i));
			}
			
			if (i%100==0 && this.incoming_monitor.isCancelled()) {return "";} //check for cancellation by the user
			if (i%1000==0) {this.incoming_monitor.setMessage("Gathering all generated hooks in one "+(int)((i*100)/this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch)+"%...");}

		}
		/*Careful: There might be Messages_to_be_included_between_hooks after the last legitimate hook, which will have maxed out index*/
		if (this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.containsKey(this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch))
		{
			sb.append(this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.get(this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch));
		}
	
		hook_str=sb.toString();
		if (this.consoleService!=null)
		{
			this.consoleService.println("// Gathering generated hooks completed, outputting to the user...");
		}
		this.incoming_monitor.setMessage("Outputting to the user...");
		return hook_str;
	}
	
	/*This function, effectively adds the code*/
	protected void backpatch_hooks_that_need_code_to_be_added_at_a_later_stage()
	{
		if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user)
		this.incoming_monitor.setMessage("Backpatching hooks that need more code...");
		
		int i;
		for (i=0;i<this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch;i++)
		{
			Address newaddr=this.internal_structures_for_hook_generation.addresses_for_which_hook_is_generated_in_order_of_appearance.get(i);
			if (this.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.containsKey(newaddr))
			{
				
				
				Instruction newinstr=this.current_program_listing.getInstructionAt(newaddr);
				//newinstr will necessarily be not null, as a hook is supposed to be generated for it
				String current_hook_for_addr=this.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.get(i);
				String hook_to_replace_later_code_placeholder="";
				
				for (String reason: this.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.get(newaddr).keySet())
				{
					if (reason=="Computed Call/Jump")
					{
						String options_for_computed_call_or_jump = this.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.get(newaddr).get(reason);
						String spaces="";
						if (options_for_computed_call_or_jump=="simple instruction")
						{
							spaces="          ";
						}
						else
						{
							//options_for_computed_call_or_jump=="start of function"
							spaces="                      ";
						}
						String arg_of_call=newinstr.toString().split(" ",2)[1].toLowerCase().trim();  //remove of CALL/BLR... and get the rest, the argument
						String mnemonic_of_command=newinstr.getMnemonicString().toLowerCase().trim();
						ComputedCallHookGenerator hookgenerator=new ComputedCallHookGenerator(this.current_program,newaddr,mnemonic_of_command,arg_of_call,"module_name_"+this.current_program_name_sanitized);
						hook_to_replace_later_code_placeholder=hook_to_replace_later_code_placeholder.concat(hookgenerator.provide_hook_code(spaces));
					}
					//Other possible reasons can go here
				}

				this.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.set(i,current_hook_for_addr.replace("PLACEHOLDER_FOR_HOOK_CODE_TO_BE_ADDED_LATER_"+newaddr,hook_to_replace_later_code_placeholder));
				
				
				if (i%100==0 && this.incoming_monitor.isCancelled()) {return ;} //check for cancellation by the user
				if (i%1000==0) {this.incoming_monitor.setMessage("Backpatching hooks that need more code "+(int)((i*100)/this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch)+"%...");}
			}
		}
				
	}
	
	
	protected void backpatch_reasons_for_advanced_hook_generation()
	{
		if (this.advancedhookoptionsdialog.isOutputReasonForHookGenCheckboxchecked)
		{
			this.maximum_number_of_reasons_to_show=Integer.parseInt(this.advancedhookoptionsdialog.ReasonForHookGenAmountcomboBox.getItemAt(this.advancedhookoptionsdialog.ReasonForHookGenAmountcomboBox.getSelectedIndex()));

			if (this.incoming_monitor.isCancelled()) {return ;} //check for cancellation by the user)
			this.incoming_monitor.setMessage("Backpatching reasons in hooks...");
			/*
			 * If that is the case, then the hook_str only has the prologue, as every other hook returned the empty string or a comment.
			 * Now it is time to go through all the hooks in the internal data structures and patch the reasons why they were hooked
			 */
			int i;
			for (i=0;i<this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch;i++)
			{
				Address current_addr =this.internal_structures_for_hook_generation.addresses_for_which_hook_is_generated_in_order_of_appearance.get(i);
				String current_hook_for_addr=this.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.get(i);
				String reason_str_for_current_hook=this.internal_structures_for_hook_generation.Addresses_for_current_hook_str.get(current_addr.toString());
				String formatted_reason_str_for_current_hook=format_reason_for_hooking(reason_str_for_current_hook);
				this.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.set(i,current_hook_for_addr.replace("PLACEHOLDER_FOR_REASONS_FOR_HOOKING_"+current_addr,formatted_reason_str_for_current_hook));
			
				if (i%100==0 && this.incoming_monitor.isCancelled()) {return ;} //check for cancellation by the user
				if (i%1000==0) {this.incoming_monitor.setMessage("Backpatching reasons in hooks "+(int)((i*100)/this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch)+"%...");}
			}
		}
		if (this.consoleService!=null)
		{
			this.consoleService.println("// Backpatching reasons completed");
		}
	}
	
	

	//Try to move backwards in the data structure to see the reference path
	String get_incoming_reference_path_string(ArrayList<ArrayList<Container_for_function_references>> all_depths_arraylists_of_function_references,int depth,int index_of_container_for_that_depth)
	{
		String retval="";
		
		int tmpdepth=depth;
		int index_of_callee_in_previous_level=index_of_container_for_that_depth;
		while(tmpdepth>=0)
		{
			Container_for_function_references tmpcontainer=all_depths_arraylists_of_function_references.get(tmpdepth).get(index_of_callee_in_previous_level);
			Function tmpfun=tmpcontainer.fun;
			index_of_callee_in_previous_level=tmpcontainer.index_of_source_at_previous_depth;
			if (tmpdepth == depth)
			{
				retval=retval.concat(tmpfun.getName(true).replace("\"", "_"));
			}
			else
			{
				retval=retval.concat("->").concat(tmpfun.getName(true).replace("\"", "_"));
			}
			tmpdepth--;
		}
		
		return retval;
	}
	
	protected Boolean user_options_allow_printing_of_params()
	{
		if (this.isAdvanced)
		{
			return (!this.advancedhookoptionsdialog.isDoNotIncludeFunParamscheckboxchecked);
		}
		return true;
	}
	
	protected void interpret_user_custom_options_on_function_hook_generation()
	{
		if (!this.isAdvanced || (this.isAdvanced && !this.advancedhookoptionsdialog.isCustomFunInterceptorHookOutputCheckboxchecked)) 
		{
			this.include_onEnter_in_function_hooks=true;
			this.include_onLeave_in_function_hooks=true;
			this.use_interceptor_attach_instead_of_replace_in_function_hooks=true;
			return;
		}
		if (this.advancedhookoptionsdialog.CustomFunInterceptorHookOutputcomboBox.getSelectedIndex()==0)
		{
			this.include_onEnter_in_function_hooks=false;
		}
		if (this.advancedhookoptionsdialog.CustomFunInterceptorHookOutputcomboBox.getSelectedIndex()==1)
		{
			this.include_onLeave_in_function_hooks=false;
		}
		if (this.advancedhookoptionsdialog.CustomFunInterceptorHookOutputcomboBox.getSelectedIndex()==2)
		{
			this.use_interceptor_attach_instead_of_replace_in_function_hooks=false;
		}
	}

	
	protected String generate_interceptor_attach_hook(Address addr,Function current_function,String function_name_with_current_addr,int parameter_count)
	{
		String hook_str="";

		hook_str=hook_str.concat("      Interceptor.attach(dynamic_address_of_"+function_name_with_current_addr+", {\n");
		if (this.include_onEnter_in_function_hooks)
		{
			hook_str=hook_str.concat("                  onEnter: function(args) {\n")
							 .concat("                      console.log(\"Entered "+function_name_with_current_addr+"\");\n");
			
			/* Put the parameters in the hook */
			if (parameter_count>=1 && user_options_allow_printing_of_params()) {
						   hook_str+="                      console.log('";
						   for (int i=0;i<parameter_count;i++)
						   {
							   hook_str+="args["+i+"]='+args["+i+"]";
							   if (i<parameter_count-1) { hook_str+="+' , "; }
							   else { hook_str+=");\n"; }
						   }
			}
			if (this.isAdvanced && this.advancedhookoptionsdialog.isOutputReasonForHookGenCheckboxchecked)
			{
				//put the placeholder for the reasons of hooking. This will be replaced when backpatching
				hook_str=hook_str.concat("                      console.log(\"Reasons for hooking: PLACEHOLDER_FOR_REASONS_FOR_HOOKING_"+addr+"\")\n");
			}
			if (this.isAdvanced && this.advancedhookoptionsdialog.isGenerateBacktraceCheckboxchecked)
			{
				hook_str=hook_str.concat(generate_backtrace_for_hook(true));
			}
			if (this.isAdvanced && this.advancedhookoptionsdialog.isIncludeCustomTextcheckboxchecked)
			{
				hook_str=hook_str.concat("                      "+this.advancedhookoptionsdialog.IncludeCustomTextTextField.getText()+"\n");
			}
			if (this.isAdvanced && can_there_be_any_reason_why_this_address_may_need_code_that_is_later_added_in_the_hook(addr))
			{
				hook_str=hook_str.concat("PLACEHOLDER_FOR_HOOK_CODE_TO_BE_ADDED_LATER_"+addr);
			}
			hook_str=hook_str.concat("                      // this.context.x0=0x1;\n")
							 .concat("                  }");
		}
		if (this.include_onEnter_in_function_hooks && this.include_onLeave_in_function_hooks) 
		{
			hook_str=hook_str.concat(",\n");
		}
		if (this.include_onLeave_in_function_hooks)
		{
			hook_str=hook_str.concat("                  onLeave: function(retval) {\n")
						 	 .concat("                      console.log(\"Exited "+function_name_with_current_addr+", retval:\"+retval);\n")
						 	 .concat("                      // retval.replace(0x1);\n")
						 	 .concat("                  }\n");
		}
		else
		{
			hook_str=hook_str.concat("\n");
		}
		hook_str=hook_str.concat("      });\n\n");
		
		return hook_str;
	}
	
	
	protected String get_frida_nativefun_str_for_parameter(DataType param_datatype)
	{
		/* it is assumed that the input parameter has been checked to not be null*/
		String str_for_param="";
		int this_param_size=param_datatype.getLength();
		if (param_datatype.toString().indexOf(" *")>=0)
		{
			//pointer
			str_for_param+="'pointer'";
		}
		else if (param_datatype.toString()=="double")
		{
			str_for_param+="'double'";
		}
		else if (param_datatype.toString()=="float")
		{
			str_for_param+="'float'";
		}
		else if (param_datatype.toString()=="int")
		{
			str_for_param+="'int'";
		}
		else if (param_datatype.toString()=="long")
		{
			str_for_param+="'long'";
		}
		else
		{
			str_for_param+="'int"+this_param_size*8+"'"; //it is assumed that the size is checked to be in an accepted range
		}
		return str_for_param;
	}
	
	
	

	protected String generate_interceptor_replace_hook(Address addr,Function current_function,String function_name_with_current_addr,int parameter_count)
	{
		String hook_str="";
		
		/*Generate strings for params*/
		String str_for_types_of_params="";
		String str_for_params_in_nativecallback="";
		
		for (int i=0;i<parameter_count;i++)
		{
			DataType this_param_datatype=current_function.getParameter(i).getDataType();

			str_for_types_of_params+=get_frida_nativefun_str_for_parameter(this_param_datatype);
			str_for_params_in_nativecallback+="arg_"+i;
			if (i<parameter_count -1)
			{
				str_for_types_of_params+=",";
				str_for_params_in_nativecallback+=",";
			}
		}
		str_for_types_of_params="["+str_for_types_of_params+"]";
		
		String str_for_return_type="";
		
		/*Generate string for return type*/
		if (current_function.getReturnType().toString()=="void")
		{
			str_for_return_type+="'void'";
		}
		else
		{
			str_for_return_type+=get_frida_nativefun_str_for_parameter(current_function.getReturnType());
		}
		String nativefunction_str="dynamic_address_of_"+function_name_with_current_addr+","+str_for_return_type+","+str_for_types_of_params;
		
		hook_str=hook_str.concat("      var NativeFunction_of_"+function_name_with_current_addr+"= new NativeFunction("+nativefunction_str+");\n");
		
		hook_str=hook_str.concat("      Interceptor.replace(dynamic_address_of_"+function_name_with_current_addr+",new NativeCallback(("+str_for_params_in_nativecallback+") => {\n");
		
		hook_str=hook_str.concat("                      console.log(\"Entered "+function_name_with_current_addr+"\");\n");
		if (this.isAdvanced && this.advancedhookoptionsdialog.isOutputReasonForHookGenCheckboxchecked)
		{
			//put the placeholder for the reasons of hooking. This will be replaced when backpatching
			hook_str=hook_str.concat("                      console.log(\"Reasons for hooking: PLACEHOLDER_FOR_REASONS_FOR_HOOKING_"+addr+"\")\n");
		}

		
			if (parameter_count>=1 && user_options_allow_printing_of_params()) {
						   hook_str+="                      console.log('";
						   for (int i=0;i<parameter_count;i++)
						   {
							   hook_str+="args["+i+"]='+arg_"+i+"";
							   if (i<parameter_count-1) { hook_str+="+' , "; }
							   else { hook_str+=");\n"; }
						   }
			}
		if (this.isAdvanced && this.advancedhookoptionsdialog.isGenerateBacktraceCheckboxchecked)
		{
			hook_str=hook_str.concat(generate_backtrace_for_hook(true));
		}
		if (this.isAdvanced && this.advancedhookoptionsdialog.isIncludeCustomTextcheckboxchecked)
		{
			hook_str=hook_str.concat("                      "+this.advancedhookoptionsdialog.IncludeCustomTextTextField.getText()+"\n");
		}
		if (this.isAdvanced && can_there_be_any_reason_why_this_address_may_need_code_that_is_later_added_in_the_hook(addr))
		{
			hook_str=hook_str.concat("PLACEHOLDER_FOR_HOOK_CODE_TO_BE_ADDED_LATER_"+addr);
		}
		//call the original function
		hook_str=hook_str.concat("                      var retval=NativeFunction_of_"+function_name_with_current_addr+"("+str_for_params_in_nativecallback+");\n");
		if (current_function.getReturnType().toString()!="void")
		{
			hook_str=hook_str.concat("                      console.log(\"Exited "+function_name_with_current_addr+", retval:\"+retval);\n");
			hook_str=hook_str.concat("                      return retval;\n");
		}
		else
		{
			hook_str=hook_str.concat("                      console.log(\"Exited "+function_name_with_current_addr+"\");\n");
		}
		hook_str=hook_str.concat("      },"+str_for_return_type+","+str_for_types_of_params+"));\n\n");
		
		return hook_str;
	}
	
	
	/*Any errors are returned with the hook str*/
	protected String identify_errors_if_interceptor_replace_is_used(Function current_function,int parameter_count)
	{
		String hook_str="";
		
		if (this.use_interceptor_attach_instead_of_replace_in_function_hooks)
		{
			return "";
		}
		if (current_function.hasVarArgs())
		{
			hook_str=hook_str.concat("      //Current function has variadic number of arguments, interceptor.replace not supported yet\n");
			return hook_str;
		}
		if (current_function.getReturnType()==null)
		{
			hook_str=hook_str.concat("      //Current function has undefined type of return value\n");
			return hook_str;
		}
		
		int size_of_returntype=current_function.getReturnType().getLength();
		//void is not ZeroLength, but getLength returns 0
		if (current_function.getReturnType().isZeroLength() || (current_function.getReturnType().toString()!="void" && size_of_returntype!=1 && size_of_returntype!=2 && size_of_returntype!=4 && size_of_returntype!=8)  )
		{
			hook_str=hook_str.concat("      //Current function has an unaccepted return type:"+current_function.getReturnType().toString()+"\n");
			return hook_str;
		}
		
		
		//check if the parameter sizes are valid
		Boolean all_param_sizes_are_valid=true;
		for (int i=0;i<parameter_count;i++)
		{
			int param_size=current_function.getParameter(i).getDataType().getLength();
			if (current_function.getParameter(i).getDataType().isZeroLength() || (param_size!=1 && param_size!=2 && param_size!=4 && param_size!=8))
			{
				all_param_sizes_are_valid=false;
				hook_str=hook_str.concat("      //Current function cannot be Interceptor.replace()'d as parameter at position "+i+" has size "+param_size+"\n");
				break;
			}
		}
		return hook_str;
	}
	
	
	
	protected String generate_backtrace_for_hook(Boolean called_from_function_start)
	{
		String hook_str="";
		String bt="";
		String ctx="";
		String spaces="";
		
		if (!this.isAdvanced || !this.advancedhookoptionsdialog.isGenerateBacktraceCheckboxchecked)
		{
			return "";
		}
		if ((this.advancedhookoptionsdialog.GenerateBacktracecomboBox.getSelectedIndex()==0 
				|| this.advancedhookoptionsdialog.GenerateBacktracecomboBox.getSelectedIndex()==1)
				&& !called_from_function_start)
		{
			return "";
		}
		
		if (called_from_function_start)
		{
			ctx="this.context";
			spaces="                      ";
		}
		else
		{
			ctx="null";
			spaces="          ";
		}

		if (this.advancedhookoptionsdialog.GenerateBacktracecomboBox.getSelectedIndex()==0
			|| this.advancedhookoptionsdialog.GenerateBacktracecomboBox.getSelectedIndex()==2)
		{
			bt="Backtracer.ACCURATE";
		}
		if (this.advancedhookoptionsdialog.GenerateBacktracecomboBox.getSelectedIndex()==1
				|| this.advancedhookoptionsdialog.GenerateBacktracecomboBox.getSelectedIndex()==3)
		{
			bt="Backtracer.FUZZY";
		}
		
		hook_str=hook_str.concat(spaces+"console.log(\"Backtrace:\"+");
		hook_str=hook_str.concat("Thread.backtrace("+ctx+", "+bt+")"
								+ ".map(DebugSymbol.fromAddress).join('\\n') + '\\n');\n");
		return hook_str;
	}
	
	
	
	/*This function generates the snippet hook, and stores it into the internal data structures*/
	protected void generate_snippet_hook_for_address( Address addr, Boolean print_debug, String reason_for_hook_generation) {
		
		if (this.internal_structures_for_hook_generation.Addresses_for_current_hook_str.containsKey(addr.toString()))
		{
			//Update the hashmap to reflect that another reason was added for the address to be hooked
			String tmpstr=this.internal_structures_for_hook_generation.Addresses_for_current_hook_str.get(addr.toString());
			this.internal_structures_for_hook_generation.Addresses_for_current_hook_str.put(addr.toString(),tmpstr.concat("|").concat(reason_for_hook_generation));
			
			//Set the intermediate message for this index
			if(this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.containsKey(this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch))
			{
				String previous_contents= this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.get(this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch);
				this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.put(this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch, 
																										previous_contents+" //Address:"+addr+", already registered interceptor for that address\n");
			}
			else
			{
				this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.put(this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch, 
						" //Address:"+addr+", already registered interceptor for that address\n");
			}
			return;
		}
		
		//Try to recalculate some parameters
		Function current_function = this.current_program.getFunctionManager().getFunctionContaining(addr);
		Instruction current_instruction=this.current_program_listing.getInstructionAt(addr); //The current address may not be in an undefined function, but it may be in an instruction

		if (current_instruction==null)
		{
			//The data structures should be updated
			String in_place_of_hook=" //Address:"+addr+", not an instruction\n";
			update_internal_data_structures(addr,in_place_of_hook,"not an instruction");
			return;
		}

		
		Address current_function_entry_point;
		Boolean we_are_at_start_of_function;
		
		if (current_function!=null)
		{
			current_function_entry_point=current_function.getEntryPoint();
			we_are_at_start_of_function=current_function_entry_point.equals(addr);
		}
		else
		{
			we_are_at_start_of_function=false;
			current_function_entry_point=null;
		}

		
		if (print_debug)
		{
			System.out.println("Address:"+addr);
			System.out.println("Program name:"+this.current_program_name);
			System.out.println("Program base:"+this.image_base);
			System.out.println("Program language:"+this.current_program_language);
			System.out.println("Program processor:"+this.current_program_processor);
			if (current_function!=null)
			{
				System.out.println("Current function:"+current_function);
				System.out.println("Current function entry point:"+current_function_entry_point);
			}
		}

		
		String hook_str="";

		/*for when we are at the start of a function*/
		String current_function_name_sanitized="";
		String function_name_with_current_addr="";
			
		if (we_are_at_start_of_function)
		{

			current_function_name_sanitized=current_function.getName(true).replaceAll("[^"+this.characters_allowed_in_variable_name+"]", "_");
			function_name_with_current_addr=current_function_name_sanitized+"_"+addr;
			int parameter_count=current_function.getParameterCount(); //May not always work, decompiler must commit the params first
			DataType current_function_returntype=current_function.getReturnType();
			String current_function_callingconventionname=current_function.getCallingConventionName();

			if (print_debug)
			{
				System.out.println("Current function name sanitized:"+current_function_name_sanitized);
				System.out.println("function_name_with_current_addr:"+function_name_with_current_addr);
				System.out.println("Current function parameter count:"+parameter_count); 
				System.out.println("Current function return type:"+current_function_returntype); 
				System.out.println("Current function calling convention name:"+current_function_callingconventionname);
			}

			//String.concat() is the fastest, but "+" is also used for code clarity. During multiple hook generations in a loop, these concatenations take the most time.
			hook_str=hook_str.concat("      var offset_of_"+function_name_with_current_addr+"=0x"+Long.toHexString(addr.getOffset()-this.image_base.getOffset())+";\n")
							 .concat("      var dynamic_address_of_"+function_name_with_current_addr+"=Module.findBaseAddress(module_name_"+this.current_program_name_sanitized+").add(offset_of_"+function_name_with_current_addr+");\n");
			
			String errors_if_interceptor_replace_is_used=identify_errors_if_interceptor_replace_is_used(current_function,parameter_count);
			//empty string means that no problems are identified
			if (errors_if_interceptor_replace_is_used=="" && !this.use_interceptor_attach_instead_of_replace_in_function_hooks)
			{
				hook_str=hook_str.concat(generate_interceptor_replace_hook(addr,current_function,function_name_with_current_addr,parameter_count));
			}
			else
			{
				hook_str=hook_str.concat(errors_if_interceptor_replace_is_used);// this is the error message from before if there is any
				hook_str=hook_str.concat(generate_interceptor_attach_hook(addr,current_function,function_name_with_current_addr,parameter_count));
			}
		}
		else
		{
			//String.concat() is the fastest, but "+" is also used for code clarity. During multiple hook generations in a loop, these concatenations take the most time.
			hook_str=hook_str.concat("      var offset_of_"+addr+"=0x"+Long.toHexString(addr.getOffset()-this.image_base.getOffset())+";\n")
							 .concat("      var dynamic_address_of_"+addr+"=Module.findBaseAddress(module_name_"+this.current_program_name_sanitized+").add(offset_of_"+addr+");\n")
			
							 .concat("      function function_to_call_when_code_reaches_"+addr+"(){\n")
							 .concat("          console.log('Reached address 0x"+addr+"');\n");
			if (this.isAdvanced && this.advancedhookoptionsdialog.isOutputReasonForHookGenCheckboxchecked)
			{
				//put the placeholder for the reasons of hooking. This will be replaced when backpatching
				hook_str=hook_str.concat("          console.log(\"Reasons for hooking: PLACEHOLDER_FOR_REASONS_FOR_HOOKING_"+addr+"\")\n");
			}
			if (this.isAdvanced && this.advancedhookoptionsdialog.isGenerateBacktraceCheckboxchecked)
			{
				hook_str=hook_str.concat(generate_backtrace_for_hook(false));
			}
			if (this.isAdvanced && this.advancedhookoptionsdialog.isIncludeCustomTextcheckboxchecked)
			{
				hook_str=hook_str.concat("          "+this.advancedhookoptionsdialog.IncludeCustomTextTextField.getText()+"\n");
			}
			if (this.isAdvanced && can_there_be_any_reason_why_this_address_may_need_code_that_is_later_added_in_the_hook(addr))
			{
				hook_str=hook_str.concat("PLACEHOLDER_FOR_HOOK_CODE_TO_BE_ADDED_LATER_"+addr);
			}
			hook_str=hook_str.concat("          //this.context.x0=0x1;\n")
							 .concat("      }\n")

							 .concat("      Interceptor.attach(dynamic_address_of_"+addr+", function_to_call_when_code_reaches_"+addr+");\n\n");

		}
		
		update_internal_data_structures(addr,hook_str,reason_for_hook_generation);
		
	}
	
	
	/* This function tries to predict, whether there might be a future reason for hooking the current address, for which special treatment (code that may later be needed to be added) is required.
	 * For example, if the current address is about a dynamic call instruction, then maybe, a later hook for the same address is asked to print the where the code will go.
	 * As the hook string is generated only once, that string will have to put a placeholder for the code that does the "special treatment". 
	 * This function only checks whether there is any chance that the current instruction may need a "special treatment" by iterating over all the implemented reasons for "special treatment", and checking if they may apply.
	 */
	protected Boolean can_there_be_any_reason_why_this_address_may_need_code_that_is_later_added_in_the_hook(Address addr)
	{
		if (this.isAdvanced && (this.advancedhookoptionsdialog.isOutDynamicCallReferencesfromFunctionCheckBoxchecked || this.advancedhookoptionsdialog.isOutDynamicCallReferencesfromAddressCheckBoxchecked))
		{
			Instruction current_instruction=this.current_program_listing.getInstructionAt(addr);
			if (current_instruction!=null && current_instruction.getFlowType().isComputed())// && current_instruction.getFlowType().isCall()) //Uncomment to restrict selection to computed hooks, do the same below
			{	
				String current_instruction_str_lowercase=current_instruction.toString().toLowerCase().trim();
				String current_instruction_mnemonic=current_instruction.getMnemonicString().toLowerCase().trim();
				if (this.current_program_language.getLanguageID().toString().indexOf("x86:LE:64")>=0 && 
						(current_instruction_mnemonic.equals("call") || current_instruction_mnemonic.equals("jmp"))
					)
				{
					return true;
				}
				
				if (this.current_program_language.getLanguageID().toString().indexOf("AARCH64:LE:64")>=0 && 
						(current_instruction_mnemonic.equals("blr") || current_instruction_mnemonic.equals("bx") ||
						 current_instruction_mnemonic.equals("br") || current_instruction_mnemonic.equals("blraaz") ||
						 current_instruction_mnemonic.equals("blrabz") )
					)
				{
					return true;
				}
			}
		}
		return false;
	}
	
	protected Boolean is_there_a_chance_that_some_hooks_generated_in_the_current_batch_require_code_that_is_later_added_in_the_hook()
	{
		if (this.isAdvanced && (this.current_program_language.getLanguageID().toString().indexOf("x86:LE:64")>=0 || this.current_program_language.getLanguageID().toString().indexOf("AARCH64:LE:64")>=0) && 
				(this.advancedhookoptionsdialog.isOutDynamicCallReferencesfromAddressCheckBoxchecked || this.advancedhookoptionsdialog.isOutDynamicCallReferencesfromFunctionCheckBoxchecked))
		{
			return true;
		}
		return false;
	}
		
	protected Boolean does_the_current_instruction_definitely_need_hook_code_to_also_be_added_later(Instruction current_instruction,String reason_for_hook_generation)
	{
		if (this.isAdvanced && current_instruction!=null && current_instruction.getFlowType().isComputed())// && current_instruction.getFlowType().isCall()) //Uncomment to restrict selection to computed hooks, do the same above
		{
			if (this.advancedhookoptionsdialog.isOutDynamicCallReferencesfromAddressCheckBoxchecked || (this.advancedhookoptionsdialog.isOutDynamicCallReferencesfromFunctionCheckBoxchecked && reason_for_hook_generation.indexOf("containing a dynamic (computed) call/jump")>=0))
			{
				String current_instruction_str_lowercase=current_instruction.toString().toLowerCase().trim();
				String current_instruction_mnemonic=current_instruction.getMnemonicString().toLowerCase().trim();
				
				if (this.current_program_language.getLanguageID().toString().indexOf("x86:LE:64")>=0 && 
						(current_instruction_mnemonic.equals("call") || current_instruction_mnemonic.equals("jmp"))
					)
					
				{
					return true;
				}
				
				if (this.current_program_language.getLanguageID().toString().indexOf("AARCH64:LE:64")>=0 && 
						(current_instruction_mnemonic.equals("blr") || current_instruction_mnemonic.equals("bx") ||
						 current_instruction_mnemonic.equals("br") || current_instruction_mnemonic.equals("blraaz") ||
						 current_instruction_mnemonic.equals("blrabz") )
					)
				{
					return true;
				}
			}
		}
		return false;
	}
	
	
	protected void update_internal_data_structures(Address addr,String hook_str, String reason_for_hook_generation)
	{
		this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch++;
		String tmpstr=String.valueOf(this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch)+"|"+reason_for_hook_generation;
		this.internal_structures_for_hook_generation.Addresses_for_current_hook_str.put(addr.toString(),tmpstr); //this is the initial placement of this address in the Addresses_for_current_hook_str data structure
		this.internal_structures_for_hook_generation.addresses_for_which_hook_is_generated_in_order_of_appearance.add(addr);
		this.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.add(hook_str);
		//if it fills the prerequisites for code to be added later, then update the Addresses_that_need_hook_code_to_be_added_at_a_later_stage
		if (this.isAdvanced && can_there_be_any_reason_why_this_address_may_need_code_that_is_later_added_in_the_hook(addr)) //first check
		{
			Instruction current_instruction=this.current_program_listing.getInstructionAt(addr);
			//Check for computed calls/jumps . This time we need to be certain that this address is supposed to contain code related to computed calls/jumps
			if (current_instruction!=null && does_the_current_instruction_definitely_need_hook_code_to_also_be_added_later(current_instruction,reason_for_hook_generation))
			{			
				HashMap<String,String> tmphm= new HashMap<String,String>();
				String reason_for_computed_call_or_jump="";
				if (this.current_program_listing.getFunctionContaining(addr)!=null && this.current_program_listing.getFunctionContaining(addr).getEntryPoint()==addr)
				{
					reason_for_computed_call_or_jump="start of function";
				}
				{
					reason_for_computed_call_or_jump="simple instruction";	
				}
				tmphm.put("Computed Call/Jump",reason_for_computed_call_or_jump);
				if (!this.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.containsKey(addr))
				{
					this.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.put(addr,tmphm );
				}
				else
				{
					//see if this address has already been registered as "Computed Call/Jump"
					if (this.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.get(addr).containsKey("Computed Call/Jump"))
					{
						;//do nothing, it's already registered
					}
					else
					{
						this.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.get(addr).put("Computed Call/Jump",reason_for_computed_call_or_jump);
					}
				}
			}
		}
	}
	
	protected String format_reason_for_hooking(String unformatted_reason)
	{
		String[] individual_reasons=unformatted_reason.split("\\|");
		int i;
		String retval="";
		int max_reasons_to_show=this.maximum_number_of_reasons_to_show;
		//starting from 1 as the first is not the reason, but the order of address, that is the increasing counter when it first appeared
		for (i=1;i<individual_reasons.length;i++)
		{
			if (i<=max_reasons_to_show)
			{
				retval=retval.concat(individual_reasons[i]);
				if (i<individual_reasons.length-1) //we haven't reached the end
				{
					retval=retval.concat("   ###   ");
				}
			}
			else
			{
				retval=retval.concat(", ... ");
				break;
			}
		}
		return retval;
	}
	

}


/*Basically a 4-tuple of data, to be inserted to data structures for keeping track of function references*/
class Container_for_function_references
{
	public Function fun;
	public int index_of_source_at_previous_depth;
	public int first_index_of_dest_at_next_depth;
	public int current_depth;
	
	public Container_for_function_references(Function fun,int index_of_source_at_previous_depth, int first_index_of_dest_at_next_depth, int current_depth)
	{
		this.fun=fun;
		this.index_of_source_at_previous_depth=index_of_source_at_previous_depth;
		this.first_index_of_dest_at_next_depth=first_index_of_dest_at_next_depth;
		this.current_depth=current_depth; 
	}

}