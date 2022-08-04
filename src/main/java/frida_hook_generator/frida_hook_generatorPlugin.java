/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package frida_hook_generator;


import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

import java.awt.datatransfer.StringSelection;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;


import docking.action.MenuData;

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
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
)
//@formatter:on
public class frida_hook_generatorPlugin extends ProgramPlugin {

	GenerateFridaHookScriptAction FridaHookScriptAction;
	GenerateFridaHookScriptAction FridaHookSnippetAction;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public frida_hook_generatorPlugin(PluginTool tool) {
		super(tool, true, true);

		String pluginName = getName();
		Boolean isSnippet=false;
		//first, create the class for script
		FridaHookScriptAction = new GenerateFridaHookScriptAction(tool, pluginName,isSnippet);
		tool.addAction(FridaHookScriptAction);
		
		isSnippet=true;
		//second, create the class for snippet
		FridaHookSnippetAction = new GenerateFridaHookScriptAction(tool, pluginName,isSnippet);
		tool.addAction(FridaHookSnippetAction);

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

		private  PluginTool incoming_plugintool;
		private  Boolean isSnippet;

		public GenerateFridaHookScriptAction(PluginTool tool, String owner, Boolean isSnippet) {
			super("Copy Frida Hook Script or Snippet", owner);
			this.incoming_plugintool = tool;
			this.isSnippet = isSnippet;
			if (isSnippet) {
				setPopupMenuData(new MenuData(new String[] { "Copy Frida Hook Snippet" },null,"Frida-Hook"));
			}
			else
			{
				setPopupMenuData(new MenuData(new String[] { "Copy Frida Hook Script" },null,"Frida-Hook"));
				//setKeyBindingData(new KeyBindingData(KeyEvent.VK_H, 0));
			}

		}

		@Override
		protected boolean isEnabledForContext(ListingActionContext context) {
			return context.getAddress() != null;
		}

		@Override
		protected void actionPerformed(ListingActionContext context) {
			System.out.println("Called Action Performed");
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
			
			Program current_program=context.getProgram();
			String current_program_name=current_program.getName();
			Address image_base=current_program.getImageBase();
			Function current_function = current_program.getFunctionManager().getFunctionContaining(addr);
			Language current_program_language = current_program.getLanguage();
			Processor current_program_processor = current_program_language.getProcessor();

			
			if (current_function != null)
			{
				Address current_function_entry_point=current_function.getEntryPoint();
				int parameter_count=current_function.getParameterCount(); //May not always work, decompiler must commit the params first
				DataType current_function_returntype=current_function.getReturnType();
				String current_function_callingconventionname=current_function.getCallingConventionName();
				
				System.out.println("Program name:"+current_program_name);
				System.out.println("Program base:"+image_base);
				System.out.println("Program language:"+current_program_language);
				System.out.println("Program processor:"+current_program_processor);
				System.out.println("Current function:"+current_function);
				System.out.println("Current function entry point:"+current_function_entry_point);
				System.out.println("Current function parameter count:"+parameter_count); 
				System.out.println("Current function return type:"+current_function_returntype); 
				System.out.println("Current function calling convention name:"+current_function_callingconventionname); 
				
				String characters_allowed="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
				String current_program_name_sanitized=current_program_name.replaceAll("[^"+characters_allowed+"]", "_");
				String hook_str="";
				
				Boolean we_are_at_start_of_function=current_function_entry_point.equals(addr);
				
				/*for when we are at the start of a function*/
				String current_function_name_sanitized="";
				String function_name_with_current_addr="";
				
				
				//Initialize variables based on whether we are at a start of a function
				if (we_are_at_start_of_function)
				{
					current_function_name_sanitized=current_function.getName().replaceAll("[^"+characters_allowed+"]", "_");
					function_name_with_current_addr=current_function_name_sanitized+"_"+addr;
					System.out.println("Current function name sanitized:"+current_function_name_sanitized);
					System.out.println("function_name_with_current_addr:"+function_name_with_current_addr);
				}

				
				
				//Create the prologue
				if (!this.isSnippet)
				{
					hook_str+="var module_name_"+current_program_name_sanitized+"='"+current_program_name+"';\n";
					hook_str+="\n";
					hook_str+="function start_timer_for_intercept() {\n"
							+ "  setTimeout(\n"
							+ "    function() {\n"
							+ "      console.log(\"Registering interceptors...\")\n";
					hook_str+="      \n";
					hook_str+="      \n";
				}
			
				
				
				
				
				
				if (we_are_at_start_of_function)
				{
					//We are at the start of the function	
					hook_str+="      var offset_of_"+function_name_with_current_addr+"=0x"+Long.toHexString(addr.getOffset()-image_base.getOffset())+";\n";
					hook_str+="      var dynamic_address_of_"+function_name_with_current_addr+"=Module.findBaseAddress(module_name_"+current_program_name_sanitized+").add(offset_of_"+function_name_with_current_addr+");\n";
					
					hook_str+="      Interceptor.attach(dynamic_address_of_"+function_name_with_current_addr+", {\n"
							+ "                 onEnter: function(args) {\n"
							+ "                    console.log(\"Entered "+function_name_with_current_addr+"\");\n";
					
					if (parameter_count>=1) {
						hook_str+="                    console.log('";
						for (int i=0;i<parameter_count;i++)
						{
							hook_str+="args["+i+"]='+args["+i+"]";
							if (i<parameter_count-1) { hook_str+="+' , "; }
							else { hook_str+=");\n"; }
						}
					}
					hook_str+="                    // this.context.x0=0x1;\n";
					hook_str+="                  },\n"
							+ "                  onLeave: function(retval) {\n"
							+ "                    console.log(\"Exited "+function_name_with_current_addr+", retval:\"+retval);\n"
							+ "                    // retval.replace(0x1);\n"
							+ "                  }\n"
							+ "       });\n\n";
								
				}
				else
				{
					hook_str+="      var offset_of_"+addr+"=0x"+Long.toHexString(addr.getOffset()-image_base.getOffset())+";\n";
					hook_str+="      var dynamic_address_of_"+addr+"=Module.findBaseAddress(module_name_"+current_program_name_sanitized+").add(offset_of_"+addr+");\n";
					
					hook_str+="      function function_to_call_when_code_reaches_"+addr+"(){\n";
					hook_str+="         console.log('Reached address 0x"+addr+"');\n";
					hook_str+="         //this.context.x0=0x1;\n";
					hook_str+="      }\n";

					hook_str+="      Interceptor.attach(dynamic_address_of_"+addr+", function_to_call_when_code_reaches_"+addr+");\n\n";
				}
				
				
				
				
				//now the epilogue
				if (!this.isSnippet)
				{
					hook_str+="      \n";
					hook_str+="      console.log(\"Registered interceptors\")\n"
							+ "    }, 2000);//milliseconds\n"
							+ "}\n"
							+ "start_timer_for_intercept();\n";
				}
				System.out.println(hook_str);
				
				//Copy to clipboard
				StringSelection stringSelection = new StringSelection(hook_str);
				Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
				clipboard.setContents(stringSelection, null);
				
				
			}
			else
			{
				System.out.println("No hook generated, current function==NULL");
				Msg.showInfo(getClass(), context.getComponentProvider().getComponent(), "Hook generation error", "No hook generated, current function is NULL.");
			}
			
		}


	}
	
	

	
	
}
