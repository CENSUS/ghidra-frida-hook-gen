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


import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.framework.model.ToolServices;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

import java.awt.datatransfer.StringSelection;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.datatransfer.Clipboard;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import docking.action.MenuData;

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;



//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "Frida Hook Generator",
	category = PluginCategoryNames.MISC,
	shortDescription = "This plugin generates a frida hook for a specified address.",
	description = "This plugin generates a frida hook for a specified address in the binary, which can be run through frida, and report when the code reaches that point. When the address is the start of a function, the plugin generates a hook with Interceptor's onEnter()/onLeave() calls. When the code is not at the start of the function, the plugin generates hooks without these calls."
	//servicesRequired = { ConsoleService.class}
)
//@formatter:on
public class frida_hook_generatorPlugin extends ProgramPlugin {

	GenerateFridaHookScriptAction FridaHookScriptAction;
	GenerateFridaHookScriptAction FridaHookSnippetAction;
	GenerateFridaHookScriptAction FridaHookAdvancedAction;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public frida_hook_generatorPlugin(PluginTool tool) {
		super(tool, true, true);

		String pluginName = getName();
		Boolean isSnippet=false;
		Boolean isAdvanced=false;
		//first, create the class for script
		FridaHookScriptAction = new GenerateFridaHookScriptAction(tool, pluginName,isSnippet,isAdvanced);
		tool.addAction(FridaHookScriptAction);
		
		isSnippet=true;
		//second, create the class for snippet
		FridaHookSnippetAction = new GenerateFridaHookScriptAction(tool, pluginName,isSnippet,isAdvanced);
		tool.addAction(FridaHookSnippetAction);
		
		
		isAdvanced=true;
		//third, create the option for the advanced hook generation
		FridaHookAdvancedAction = new GenerateFridaHookScriptAction(tool, pluginName,isSnippet,isAdvanced);
		tool.addAction(FridaHookAdvancedAction);
		

		// TODO: Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor for FridaHookAction";
		FridaHookScriptAction.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}
	
	
	
	public class GenerateFridaHookScriptAction extends ListingContextAction {

		private PluginTool incoming_plugintool;
		private Boolean isSnippet;
		private Boolean isAdvanced;
		private Boolean include_onEnter_in_function_hooks;
		private Boolean include_onLeave_in_function_hooks;
		private ConsoleService consoleService;
		
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
		//This is a hashmap that contains for which addresses a hook has been generated, in the current batch. It is a data structure held so that interceptor hooks are not being created for the same address twice. The value of the field will be in the following format: <index in sequence of addresses>|<reason for hook 1>|<reason for hook 2>|....
		private HashMap<String, String> Addresses_for_current_hook_str;
		private int how_many_addresses_have_been_hooked_so_far_in_this_batch;
		//This ArrayList keeps the addresses for which a hook is generated, by order of appearance. The reason is that when reasons of hooking are also printed in the console, we might need fast lookup for the address that came at position X.
		private ArrayList<Address> addresses_for_which_hook_is_generated_in_order_of_appearance;
		//This ArrayList keeps the hooks which are generated for every individual address, in order of appearance.
		private ArrayList<String> hooks_generated_per_address_in_order_of_appearance;
		
		//The following three parameters are related to the background task that runs the advanced hook generation
		private Advanced_hook_generation_task advanced_hook_generation_task;
		protected volatile TaskMonitor incoming_monitor;
		protected volatile String result_of_advanced_hook_generation;
				
		public GenerateFridaHookScriptAction(PluginTool tool, String owner, Boolean isSnippet, Boolean isAdvanced) {
			super("Copy Frida Hook Script or Snippet", owner);
			this.incoming_plugintool = tool;
			this.isSnippet = isSnippet;
			this.isAdvanced = isAdvanced;

			if (isSnippet && !isAdvanced) {
				setPopupMenuData(new MenuData(new String[] { "Copy Frida Hook Snippet" },null,"Frida-Hook"));
			}
			else if (!isSnippet && !isAdvanced)
			{
				setPopupMenuData(new MenuData(new String[] { "Copy Frida Hook Script" },null,"Frida-Hook"));
				//setKeyBindingData(new KeyBindingData(KeyEvent.VK_H, 0));
			}
			else if (isAdvanced)
			{
				setPopupMenuData(new MenuData(new String[] { "Create Advanced Frida Hook..." },null,"Frida-Hook"));
			}

		}

		@Override
		protected boolean isEnabledForContext(ListingActionContext context) {
			return context.getAddress() != null;
		}

		@Override
		protected void actionPerformed(ListingActionContext context) {
			System.out.println("Called Action Performed");
			
			//Initialize the internal data structures. This should be done here and not in the constructor, as we purposefully do not want to keep state between two invocations of the plugin (the user might have deleted some code, we don't really know what is in the .js file)
			this.Addresses_for_current_hook_str= new HashMap<String, String>();
			this.how_many_addresses_have_been_hooked_so_far_in_this_batch=0;
			this.addresses_for_which_hook_is_generated_in_order_of_appearance=new ArrayList<Address>();
			this.hooks_generated_per_address_in_order_of_appearance=new ArrayList<String>();
			this.include_onEnter_in_function_hooks=true;
			this.include_onLeave_in_function_hooks=true;
			if (this.isAdvanced)
			{
				this.advancedhookoptionsdialog = new AdvancedHookOptionsDialog("Advanced Frida Hook Options",tool);
			}
			
			
			Address addr = context.getAddress();
			ProgramLocation location = context.getLocation();
			if (location instanceof OperandFieldLocation) {
				Address a = ((OperandFieldLocation) location).getRefAddress();
				if (a != null) {
					addr = a;
				}
			}
			System.out.println("Address:"+addr);
			System.out.println("Location:"+location);
			System.out.println("Program:"+context.getProgram());
			
			//System.out.println("Code unit:"+context.getCodeUnit());
			//System.out.println("Global Context:"+context.getGlobalContext());
			//System.out.println("Source component:"+context.getSourceComponent());
			
			//Initialize the console
			this.consoleService=this.incoming_plugintool.getService(ConsoleService.class); //Note: If this line is called when initializing the tool (in the constructor), then the consoleService will be null

			if (this.isAdvanced)
			{
				System.gc(); //If advanced hooks are created many times, this may lead to a lot of memory being used
				this.advancedhookoptionsdialog.fetch_advanced_hook_options(addr, current_program);
				if (!this.advancedhookoptionsdialog.isOKpressed)
				{
					System.out.println("User clicked at advanced options but did not press OK");
					return;
				}
				//Set up the boolean variables affecting the function hook generation
				interpret_user_custom_options_on_function_hook_generation();
			}
			
			/* Initialize some other useful things*/
			this.current_program = context.getProgram();
			this.current_program_name = this.current_program.getName();
			Function current_function = this.current_program.getFunctionManager().getFunctionContaining(addr);
			this.current_program_listing = this.current_program.getListing();
			this.current_program_name_sanitized = this.current_program_name.replaceAll("[^"+this.characters_allowed_in_variable_name+"]", "_");
			this.image_base = this.current_program.getImageBase();
			this.current_program_language = this.current_program.getLanguage();
			this.current_program_processor = this.current_program_language.getProcessor();

			
			if (current_function==null && !this.isAdvanced)
			{
				//No advanced hooking, tried to hook address which is not in a function
				System.out.println("No hook generated, current function==NULL");
				Msg.showInfo(getClass(), context.getComponentProvider().getComponent(), "Hook generation error", "No hook generated, current function is NULL.");
				return;
			}
			
			//Else, begin creating the hook
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
			if (!this.isSnippet)
			{
				hook_str+=generate_prologue_for_address(context,addr,true);
			}
			
			//handle the simple right click case
			if (!this.isAdvanced)
			{
				hook_str=hook_str.concat(handle_simple_right_click_hook_generation(context,addr,true));
			}
			//handle all Advanced cases
			if (this.isAdvanced)
			{
				//Initialize the task which will do the job
				this.advanced_hook_generation_task=new Advanced_hook_generation_task("Generating Hooks...",this.incoming_plugintool,this,context,addr,false);
				this.incoming_monitor=null;
				this.result_of_advanced_hook_generation="";
				this.incoming_plugintool.execute(advanced_hook_generation_task); //this actually runs the handle_advanced_hook_generation() function, as well as the reason backpatching if it is required
				//Due to the way the task is constructed (modal = true, waitfortaskcompleted=true), the code will block here until the task is done.
				hook_str=hook_str.concat(this.result_of_advanced_hook_generation); //The result is placed in this.result_of_advanced_hook_generation
			}

			if (this.isAdvanced)
			{
				hook_str=hook_str.concat("//Attempted to generate hooks for "+this.Addresses_for_current_hook_str.size()+" different addresses\n");
			}
			
			//Now, the epilogue
			if (!this.isSnippet)
			{
				hook_str+=generate_epilogue_for_address(context,addr,true);
			}
			
			
			handle_output(hook_str);
			
			//cleanup
			if (this.isAdvanced)
			{
				//Try to free as much memory as possible at the end
				this.advancedhookoptionsdialog=null;
				this.Addresses_for_current_hook_str=null;
				this.addresses_for_which_hook_is_generated_in_order_of_appearance=null;
				this.hooks_generated_per_address_in_order_of_appearance=null;
				this.incoming_monitor=null;
				this.result_of_advanced_hook_generation="";
				this.advanced_hook_generation_task=null;
				System.gc();
			}
					
		}
		
		
		protected String generate_epilogue_for_address(ListingActionContext context, Address addr, Boolean print_debug) {
			
			String hook_str="";
			
			if (!this.isAdvanced || (this.isAdvanced && !this.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked) || (this.isAdvanced && this.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==0))
			{
				//default method
				hook_str+="      \n";
				hook_str+="      console.log(\"Registered interceptors.\");\n"
						+ "    }, 2000);//milliseconds\n"
						+ "}\n"
						+ "start_timer_for_intercept();\n";
			}
			if (this.isAdvanced && this.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==1)
			{
				//dlopen() method
				hook_str+="      \n"
						+ "      console.log(\"Registered interceptors.\");\n"
						+ "}\n";
			}
			
			return hook_str;
					
		}
		
		
		protected String generate_prologue_for_address(ListingActionContext context, Address addr, Boolean print_debug) {
			
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
						+ "        we_encountered_the_lib_in_the_initial_pass_of_the_loaded_modules=true;\n"
						+ "        register_interceptors();\n"
						+ "        break;\n"
						+ "    }\n"
						+ "    var exports = process_modules[i].enumerateExports()\n"
						+ "    for(var j=0;j<exports.length;j++)\n"
						+ "    {\n"
						+ "        //if (exports[j].name.indexOf(\"dlopen\")>=0) //there may be more than one dlopen related functions, like __libc_dlopen_mode()\n"
						+ "        if (exports[j].name==\"dlopen\")\n"
						+ "        {\n"
						+ "            console.log(JSON.stringify(exports[j]))\n"
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
						+ "      console.log(\"Registering interceptors...\")\n"
						+ "      \n\n";
				
			}
			return hook_str;
			
		}
		

		protected void handle_output(String hook_str)
		{
			Boolean user_has_cancelled_do_not_destroy_clipboard=false;
			if (this.isAdvanced && this.advanced_hook_generation_task!=null && this.advanced_hook_generation_task.is_cancelled)
			{
				//This is the case where the user has manually cancelled
				hook_str="// User has cancelled\n";
				user_has_cancelled_do_not_destroy_clipboard=true;
			}
			//Print to eclipse console
			System.out.println(hook_str);
			
			if (!user_has_cancelled_do_not_destroy_clipboard)
			{
				//Copy to clipboard
				StringSelection stringSelection = new StringSelection(hook_str);
				Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
				clipboard.setContents(stringSelection, null);
			}				
			
			//Print to Ghidra Console	
			if (this.consoleService!=null)
			{
				this.consoleService.print(hook_str);
			}
			else
			{
				System.out.println("Can't print to console because consoleService is null");
			}
		}
		
		
		
		
		
		
		protected String handle_simple_right_click_hook_generation(ListingActionContext context, Address addr, Boolean print_debug)
		{
			return generate_snippet_hook_for_address(context,addr,print_debug,"Simple Right Click");
		}
		
		
		
		
		/* This is a big and complex function, handling all sub-cases for the advanced hook generation*/
		protected String handle_advanced_hook_generation(ListingActionContext context, Address addr, Boolean print_debug)
		{
			Function current_function = this.current_program.getFunctionManager().getFunctionContaining(addr);
			String advanced_hook_str="";
			
			if (this.consoleService!=null)
			{
				this.consoleService.println("// Generating hooks... Please wait");
			}
			
			if (this.incoming_monitor.isCancelled()) {this.advanced_hook_generation_task.is_cancelled=true; return "";} //check for cancellation by the user
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
							advanced_hook_str=advanced_hook_str.concat(generate_snippet_hook_for_address(context,newaddr,true,"Address referencing address "+addr+" , referenceType:"+ref.getReferenceType()));
						}
						if (this.advancedhookoptionsdialog.isFunctionsReferencingAddressCheckBoxchecked)
						{
							Function newfun=this.current_program.getFunctionManager().getFunctionContaining(newaddr);
							if (newfun!=null)
							{
								advanced_hook_str=advanced_hook_str.concat(generate_snippet_hook_for_address(context,newfun.getEntryPoint(),true,"Function containing address "+newaddr+" that references to initial address "+addr+" through referenceType:"+ref.getReferenceType()));
						
							}	
						}
					}					
				}
			}
			
			if (this.incoming_monitor.isCancelled()) {this.advanced_hook_generation_task.is_cancelled=true; return "";} //check for cancellation by the user

			
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
						advanced_hook_str=advanced_hook_str.concat(generate_snippet_hook_for_address(context,newaddr,true,"Address referencing function at "+current_function.getEntryPoint()+" named "+current_function.getName(true)+" containing address "+addr+", through referenceType:"+ref.getReferenceType()));
					}
				}
				
			}
			
			if (this.incoming_monitor.isCancelled()) {this.advanced_hook_generation_task.is_cancelled=true; return "";} //check for cancellation by the user
		
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
						advanced_hook_str=advanced_hook_str.concat(generate_snippet_hook_for_address(context,newfun.getEntryPoint(),false,"Incoming function call reference from function at "+newfun.getEntryPoint()+" named "+newfun.getName(true)+", to final current function "+current_function.getName(true)+" containing address "+addr+", after call depth="+i+", using call path:"+reference_path_string));
					
						if (j%100==0 && this.incoming_monitor.isCancelled()) {this.advanced_hook_generation_task.is_cancelled=true; return "";} //check for cancellation by the user
					}
					if (this.incoming_monitor.isCancelled()) {this.advanced_hook_generation_task.is_cancelled=true; return "";} //check for cancellation by the user
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
						advanced_hook_str=advanced_hook_str.concat(generate_snippet_hook_for_address(context,newfun.getEntryPoint(),false,"Outgoing function call reference to function at "+newfun.getEntryPoint()+" named "+newfun.getName(true)+", from initial current function "+current_function.getName(true)+" containing address "+addr+", after call depth="+i+", using call path:"+reference_path_string));
						
						if (j%100==0 && this.incoming_monitor.isCancelled()) {this.advanced_hook_generation_task.is_cancelled=true; return "";} //check for cancellation by the user
					}
					if (this.incoming_monitor.isCancelled()) {this.advanced_hook_generation_task.is_cancelled=true; return "";} //check for cancellation by the user
				}
				
			}
			
			if (this.incoming_monitor.isCancelled()) {this.advanced_hook_generation_task.is_cancelled=true; return "";} //check for cancellation by the user
			
			
			
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
				
				System.out.println("RangeAddressesNum: "+this.advancedhookoptionsdialog.RangeAddressesNum);

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
							advanced_hook_str=advanced_hook_str.concat(generate_snippet_hook_for_address(context,newaddr,false,"Address hook in range of initial address "+addr+". Offset from that: "+num_of_addresses_advanced+" addresses, "+num_of_instructions_advanced+" instructions, "+num_of_functions_advanced+" functions."));
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

						if (number_of_times_iterated%100==0 && this.incoming_monitor.isCancelled()) {this.advanced_hook_generation_task.is_cancelled=true; return "";} //check for cancellation by the user
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
			
			
			/* Range hooking, for functions */
			if (this.advancedhookoptionsdialog.isRangeFunctionsCheckBoxchecked && this.advancedhookoptionsdialog.RangeFunctionsNum>0)
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
					advanced_hook_str=advanced_hook_str.concat(generate_snippet_hook_for_address(context,newfun.getEntryPoint(),false,"Function hook in range of initial address "+addr+". Offset from that: "+num_of_addresses_advanced+" addresses, "+num_of_functions_advanced+" functions."));
					num_of_functions_advanced++; //in this case, 1 function means -> hook the present one

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
					advanced_hook_str=advanced_hook_str.concat(generate_snippet_hook_for_address(context,newfun.getEntryPoint(),false,"Function hook in range of initial address "+addr+". Offset from that: "+num_of_addresses_advanced+" addresses, "+num_of_functions_advanced+" functions."));
				
					if (num_of_functions_advanced%100==0 && this.incoming_monitor.isCancelled()) {this.advanced_hook_generation_task.is_cancelled=true; return "";} //check for cancellation by the user
					if (num_of_functions_advanced%1000==0) {this.incoming_monitor.setMessage("Range for functions "+num_of_functions_advanced+"...");}
				}

			}
			
			/* Function name regex hooking */
			if (this.advancedhookoptionsdialog.isFunctionRegexCheckBoxchecked)
			{
				String regex_for_fun_name=this.advancedhookoptionsdialog.FunctionRegexTextField.getText();
				Pattern pattern= Pattern.compile(regex_for_fun_name,Pattern.CASE_INSENSITIVE);
				FunctionIterator fun_iter=this.current_program_listing.getFunctions(true);
				int num_of_functions_processed=0;
				
				if (this.incoming_monitor.isCancelled()) {this.advanced_hook_generation_task.is_cancelled=true; return "";}
				this.incoming_monitor.setMessage("Function hooking by regex....");
				
				while(fun_iter!=null && fun_iter.hasNext())
				{
					Function newfun=fun_iter.next();
					num_of_functions_processed++;
					String name_of_newfun=newfun.getName(true);
					if (pattern.matcher(name_of_newfun).matches())
					{
						advanced_hook_str=advanced_hook_str.concat(generate_snippet_hook_for_address(context,newfun.getEntryPoint(),false,"Function hook to function "+name_of_newfun+" due to matching regex:"+regex_for_fun_name));
					}
					if (num_of_functions_processed%100==0 && this.incoming_monitor.isCancelled()) {this.advanced_hook_generation_task.is_cancelled=true; return "";} //check for cancellation by the user
				}
				
			
			}
			
			
			if (this.consoleService!=null)
			{
				this.consoleService.println("// Hook Generated");
			}				
			
			this.advanced_hook_generation_task.is_hookgen_completed=true;
			return advanced_hook_str;
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
					retval="->".concat(tmpfun.getName(true)).concat(retval);
				}
				else
				{
					retval=tmpfun.getName(true).concat(retval);
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
		
		
		protected String backpatch_reasons_for_advanced_hook_generation()
		{
			String hook_str="";
			if (this.advancedhookoptionsdialog.isOutputReasonForHookGenCheckboxchecked)
			{
				this.maximum_number_of_reasons_to_show=Integer.parseInt(this.advancedhookoptionsdialog.ReasonForHookGenAmountcomboBox.getItemAt(this.advancedhookoptionsdialog.ReasonForHookGenAmountcomboBox.getSelectedIndex()));

				if (this.incoming_monitor.isCancelled()) {this.advanced_hook_generation_task.is_cancelled=true; return "";} //check for cancellation by the user)
				this.incoming_monitor.setMessage("Backpatching reasons in hooks...");
				/*
				 * If that is the case, then the hook_str only has the prologue, as every other hook returned the empty string or a comment.
				 * Now it is time to go through all the hooks in the internal data structures and patch the reasons why they were hooked
				 */
				int i;
				for (i=0;i<this.how_many_addresses_have_been_hooked_so_far_in_this_batch;i++)
				{
					Address current_addr =this.addresses_for_which_hook_is_generated_in_order_of_appearance.get(i);
					String current_hook_for_addr=this.hooks_generated_per_address_in_order_of_appearance.get(i);
					String reason_str_for_current_hook=this.Addresses_for_current_hook_str.get(current_addr.toString());
					String formatted_reason_str_for_current_hook=format_reason_for_hooking(reason_str_for_current_hook);
					hook_str=hook_str.concat(current_hook_for_addr.replace("PLACEHOLDER_FOR_REASONS_FOR_HOOKING_"+current_addr,formatted_reason_str_for_current_hook));
				
					if (i%100==0 && this.incoming_monitor.isCancelled()) {this.advanced_hook_generation_task.is_cancelled=true; return "";} //check for cancellation by the user
					if (i%1000==0) {this.incoming_monitor.setMessage("Backpatching reasons in hooks "+(int)((i*100)/how_many_addresses_have_been_hooked_so_far_in_this_batch)+"%...");}
				}
			}
			this.advanced_hook_generation_task.is_backpatching_completed=true;
			if (this.consoleService!=null)
			{
				this.consoleService.println("// Backpatching reasons completed");
			}
			
			return hook_str;
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
					retval=retval.concat(tmpfun.getName(true));
				}
				else
				{
					retval=retval.concat("->").concat(tmpfun.getName(true));
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
		}

		

		protected String generate_snippet_hook_for_address(ListingActionContext context, Address addr, Boolean print_debug, String reason_for_hook_generation) {
			
			if (this.Addresses_for_current_hook_str.containsKey(addr.toString()))
			{
				//Just update the hashmap to reflect that another reason was added for the address to be hooked
				String tmpstr=Addresses_for_current_hook_str.get(addr.toString());
				this.Addresses_for_current_hook_str.put(addr.toString(),tmpstr.concat("|").concat(reason_for_hook_generation));
				if (this.isAdvanced && this.advancedhookoptionsdialog.isOutputReasonForHookGenCheckboxchecked)
				{
					return ""; //In the special case where the reasoning must be printed, return nothing. The hook will be generated all at once at the end, with the reason backpatching
				}
				else
				{
					return (" //Address:"+addr+", already registered interceptor for that address\n");
				}
			}
			
			//Try to recalculate some parameters
			Function current_function = this.current_program.getFunctionManager().getFunctionContaining(addr);
			
			if (current_function==null)
			{
				//The data structures should be updated
				String in_place_of_hook=" //Address:"+addr+", not in a function\n";
				update_internal_data_structures(addr,in_place_of_hook,"not in a function");
				if (this.isAdvanced && this.advancedhookoptionsdialog.isOutputReasonForHookGenCheckboxchecked)
				{
					return ""; //In the special case where the reasoning must be printed, return nothing. The hook will be generated all at once at the end, with the reason backpatching
				}
				else
				{
					return (in_place_of_hook);
				}
			}

			Address current_function_entry_point=current_function.getEntryPoint();

			
			if (print_debug)
			{
				System.out.println("Address:"+addr);
				System.out.println("Program name:"+this.current_program_name);
				System.out.println("Program base:"+this.image_base);
				System.out.println("Program language:"+this.current_program_language);
				System.out.println("Program processor:"+this.current_program_processor);
				System.out.println("Current function:"+current_function);
				System.out.println("Current function entry point:"+current_function_entry_point);
			}

			
			String hook_str="";
			
			Boolean we_are_at_start_of_function=current_function_entry_point.equals(addr);
			
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
								 .concat("      var dynamic_address_of_"+function_name_with_current_addr+"=Module.findBaseAddress(module_name_"+this.current_program_name_sanitized+").add(offset_of_"+function_name_with_current_addr+");\n")
				
								 .concat("      Interceptor.attach(dynamic_address_of_"+function_name_with_current_addr+", {\n");
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
				hook_str=hook_str.concat("          //this.context.x0=0x1;\n")
								 .concat("      }\n")

								 .concat("      Interceptor.attach(dynamic_address_of_"+addr+", function_to_call_when_code_reaches_"+addr+");\n\n");

			}
			

			update_internal_data_structures(addr,hook_str,reason_for_hook_generation);
			if (this.isAdvanced && this.advancedhookoptionsdialog.isOutputReasonForHookGenCheckboxchecked)
			{
				return ""; //In the special case where the reasoning must be printed, return nothing. The hook will be generated all at once at the end, with the reason backpatching
			}
			else
			{
				//the normal case
				return hook_str;
			}
			
			
		}
		
		
		
		
		protected void update_internal_data_structures(Address addr,String hook_str, String reason_for_hook_generation)
		{
			this.how_many_addresses_have_been_hooked_so_far_in_this_batch++;
			String tmpstr=String.valueOf(this.how_many_addresses_have_been_hooked_so_far_in_this_batch)+"|"+reason_for_hook_generation;
			this.Addresses_for_current_hook_str.put(addr.toString(),tmpstr);
			this.addresses_for_which_hook_is_generated_in_order_of_appearance.add(addr);
			this.hooks_generated_per_address_in_order_of_appearance.add(hook_str);
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

