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
import resources.Icons;

import java.awt.datatransfer.StringSelection;
import java.util.List;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.datatransfer.Clipboard;
import java.util.ArrayList;
import java.util.HashMap;

import docking.action.MenuData;

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;


/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
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
		private ConsoleService consoleService;
		
		private Program current_program; 
		private String current_program_name;
		private String current_program_name_sanitized;
		private Listing current_program_listing;
		private Language current_program_language;
		private Address image_base;
		private Processor current_program_processor;
		private String characters_allowed_in_variable_name="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
		private AdvancedHookOptionsDialog advancedhookoptionsdialog;
		//This is a hashmap that contains for which addresses a hook has been generated, in the current batch. It is a data structure held so that interceptor hooks are not being created for the same address twice. The value of the field will be n the following format: <index in sequence of addresses>|<reason for hook 1>|<reason for hook 2>|....
		private HashMap<String, String> Addresses_for_current_hook_str;
		private int how_many_addresses_have_been_hooked_so_far_in_this_batch;
		//This ArrayList keeps the addresses for which a hook is generated, by order of appearance. The reason is that in the future (when reasons of hooking are also printed in the console), we might need fast lookup for the address that came at position X.
		private ArrayList<String> addresses_for_which_hook_is_generated_in_order_of_appearance;
		//This ArrayList keeps the hooks which are generated for every individual address, in order of appearance.
		private ArrayList<String> hooks_generated_per_address_in_order_of_appearance;
		
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
			this.addresses_for_which_hook_is_generated_in_order_of_appearance=new ArrayList<String>();
			this.hooks_generated_per_address_in_order_of_appearance=new ArrayList<String>();
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
			}
			
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
				hook_str=hook_str.concat(handle_advanced_hook_generation(context,addr,true));
			}
			
			//now the epilogue
			if (!this.isSnippet)
			{
				hook_str+=generate_epilogue_for_address(context,addr,true);
			}
			
			
			
			//Now, out put the string. Copy to clipboard, print to console...
			handle_output(hook_str);
					
		}
		
		
		protected String generate_epilogue_for_address(ListingActionContext context, Address addr, Boolean print_debug) {
			
			String hook_str="";
			
			hook_str+="      \n";
			hook_str+="      console.log(\"Registered interceptors\")\n"
					+ "    }, 2000);//milliseconds\n"
					+ "}\n"
					+ "start_timer_for_intercept();\n";
			
			return hook_str;
					
		}
		
		
		protected String generate_prologue_for_address(ListingActionContext context, Address addr, Boolean print_debug) {
			
			String hook_str="";
			
			hook_str+="var module_name_"+this.current_program_name_sanitized+"='"+this.current_program_name+"';\n";
			hook_str+="\n";
			hook_str+="function start_timer_for_intercept() {\n"
					+ "  setTimeout(\n"
					+ "    function() {\n"
					+ "      console.log(\"Registering interceptors...\")\n";
			hook_str+="      \n";
			hook_str+="      \n";
			
			return hook_str;
					
		}
		

		protected void handle_output(String hook_str)
		{
			//Print to eclipse console
			System.out.println(hook_str);
			
			//Copy to clipboard
			StringSelection stringSelection = new StringSelection(hook_str);
			Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
			clipboard.setContents(stringSelection, null);
							
			
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
		
		
		
		
		
		protected String handle_advanced_hook_generation(ListingActionContext context, Address addr, Boolean print_debug)
		{
			Function current_function = this.current_program.getFunctionManager().getFunctionContaining(addr);
			String advanced_hook_str="";
			
			if (this.advancedhookoptionsdialog.isReferencestoAddressCheckBoxchecked && current_function!=null)
			{
				Instruction current_instruction=this.current_program_listing.getInstructionAt(addr);
				if (current_instruction!=null)
				{

					ReferenceIterator ref_iter= current_instruction.getReferenceIteratorTo();
					while(ref_iter.hasNext())
					{
						Reference ref = ref_iter.next();
						Address newaddr=ref.getFromAddress();
						advanced_hook_str=advanced_hook_str.concat(generate_snippet_hook_for_address(context,newaddr,true,"Address Reference to address "+addr));
					}					
				}
			}
			
			
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
						advanced_hook_str=advanced_hook_str.concat(generate_snippet_hook_for_address(context,newaddr,true,"Address Reference to function at "+current_function.getEntryPoint()+" containing address "+addr));
					}
				}
				
			}
		
			if (this.advancedhookoptionsdialog.isFunctionsReferencingFunctionCheckboxchecked && current_function!=null)
			{
				Instruction instruction_of_current_function_start=current_program_listing.getInstructionAt(current_function.getEntryPoint());
				
				if (instruction_of_current_function_start!=null)
				{
					ReferenceIterator ref_iter= instruction_of_current_function_start.getReferenceIteratorTo();
					while(ref_iter.hasNext())
					{
						Reference ref = ref_iter.next();
						Address newaddr=ref.getFromAddress();
						Function new_function = this.current_program.getFunctionManager().getFunctionContaining(newaddr);
						if (new_function!=null)
						{
							advanced_hook_str=advanced_hook_str.concat(generate_snippet_hook_for_address(context,new_function.getEntryPoint(),true,"Function reference to function at "+current_function.getEntryPoint()+" containing address "+addr));
						}
					}
				}
				
			}
			
			return advanced_hook_str;
		}
		
		
		
		
		
		
		
	
		
		
		
		
		
		
		

		protected String generate_snippet_hook_for_address(ListingActionContext context, Address addr, Boolean print_debug, String reason_for_hook_generation) {
			
			if (this.Addresses_for_current_hook_str.containsKey(addr.toString()))
			{
				//Just update the hashmap to reflect that another reason was added for the address to be hooked
				String tmpstr=Addresses_for_current_hook_str.get(addr.toString());
				this.Addresses_for_current_hook_str.put(addr.toString(),tmpstr.concat("|").concat(reason_for_hook_generation));
				return (" //Address:"+addr+", already registered interceptor for that address\n");
			}
			
			//Try to recalculate some parameters
			Function current_function = this.current_program.getFunctionManager().getFunctionContaining(addr);
			
			if (current_function==null)
			{
				//The data structures should be updated
				String in_place_of_hook=" //Address:"+addr+", not in a function\n";
				update_internal_data_structures(addr,in_place_of_hook,"not in a function");
				return (in_place_of_hook);
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
				//We are at the start of the function	
				
				current_function_name_sanitized=current_function.getName().replaceAll("[^"+this.characters_allowed_in_variable_name+"]", "_");
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
				
								 .concat("      Interceptor.attach(dynamic_address_of_"+function_name_with_current_addr+", {\n")
								 .concat("                 onEnter: function(args) {\n")
								 .concat("                    console.log(\"Entered "+function_name_with_current_addr+"\");\n");
				
				if (parameter_count>=1) {
							   hook_str+="                    console.log('";
							   for (int i=0;i<parameter_count;i++)
							   {
								   hook_str+="args["+i+"]='+args["+i+"]";
								   if (i<parameter_count-1) { hook_str+="+' , "; }
								   else { hook_str+=");\n"; }
							   }
				}
				hook_str=hook_str.concat("                    // this.context.x0=0x1;\n")
								 .concat("                  },\n")
								 .concat("                  onLeave: function(retval) {\n")
								 .concat("                    console.log(\"Exited "+function_name_with_current_addr+", retval:\"+retval);\n")
								 .concat("                    // retval.replace(0x1);\n")
								 .concat("                  }\n")
								 .concat("       });\n\n");
							
			}
			else
			{
				//String.concat() is the fastest, but "+" is also used for code clarity. During multiple hook generations in a loop, these concatenations take the most time.
				hook_str=hook_str.concat("      var offset_of_"+addr+"=0x"+Long.toHexString(addr.getOffset()-this.image_base.getOffset())+";\n")
								 .concat("      var dynamic_address_of_"+addr+"=Module.findBaseAddress(module_name_"+this.current_program_name_sanitized+").add(offset_of_"+addr+");\n")
				
								 .concat("      function function_to_call_when_code_reaches_"+addr+"(){\n")
								 .concat("         console.log('Reached address 0x"+addr+"');\n")
								 .concat("         //this.context.x0=0x1;\n")
								 .concat("      }\n")

								 .concat("      Interceptor.attach(dynamic_address_of_"+addr+", function_to_call_when_code_reaches_"+addr+");\n\n");

			}
			

			update_internal_data_structures(addr,hook_str,reason_for_hook_generation);
			return hook_str;
			
			
			
		}
		
		
		
		
		protected void update_internal_data_structures(Address addr,String hook_str, String reason_for_hook_generation)
		{
			this.how_many_addresses_have_been_hooked_so_far_in_this_batch++;
			String tmpstr=String.valueOf(this.how_many_addresses_have_been_hooked_so_far_in_this_batch)+"|"+reason_for_hook_generation;
			this.Addresses_for_current_hook_str.put(addr.toString(),tmpstr);
			this.addresses_for_which_hook_is_generated_in_order_of_appearance.add(addr.toString());
			this.hooks_generated_per_address_in_order_of_appearance.add(hook_str);
		}
		

	}
	
		
}

