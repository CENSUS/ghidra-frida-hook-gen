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


import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.framework.model.ToolServices;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
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
	shortDescription = "This plugin provides right-click options for fast generation of Frida hooks",
	description = "This plugin generates a right-click options for fast generation of Frida hook code, for specified addresses in the binary. That (Javascript) code can be run through Frida, and at the very least it will report when the code reaches the specified points. When the hooked address is the start of a function, the plugin generates a hook with Interceptor's onEnter()/onLeave() calls. When the code is not at the start of the function, the plugin generates hooks without these calls."
	//servicesRequired = { ConsoleService.class}
)
//@formatter:on
public class FridaHookGeneratorPlugin extends ProgramPlugin {

	GenerateFridaHookScriptAction FridaHookScriptAction;
	GenerateFridaHookScriptAction FridaHookSnippetAction;
	GenerateFridaHookScriptAction FridaHookAdvancedAction;
	SelectionHookGenerationAction SearchSelectionAction;
	StructAccessCodeGenerationAction StructAccessAction;
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public FridaHookGeneratorPlugin(PluginTool tool) {
		//super(tool, true, true);
		super(tool);

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
		

		// TODO: Customize help
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor for FridaHookAction";
		FridaHookScriptAction.setHelpLocation(new HelpLocation(topicName, anchorName));
		
		/*Now add the plugin part which allows for hook generation based on a selection*/
		SearchSelectionAction=new SelectionHookGenerationAction(this,this.getProgramSelection());
		tool.addAction(SearchSelectionAction);
		
		/*And the plugin part which allows for generation of code for struct getters and setters*/
		StructAccessAction=new StructAccessCodeGenerationAction(this,false);
		tool.addAction(StructAccessAction);
		
		/*And the same thing, but also recursively for substructs*/ 
		StructAccessAction=new StructAccessCodeGenerationAction(this,true);
		tool.addAction(StructAccessAction);
				
	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}
	
}


