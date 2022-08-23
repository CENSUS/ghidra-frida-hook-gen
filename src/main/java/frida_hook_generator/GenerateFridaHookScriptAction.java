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
import ghidra.app.context.ListingContextAction;
import ghidra.app.services.ConsoleService;
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
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;


public class GenerateFridaHookScriptAction extends ListingContextAction {

	private PluginTool incoming_plugintool;
	private Boolean isSnippet;
	private Boolean isAdvanced;
	protected String final_hook_str;
	private Standard_hook_generation_task hook_generation_task;
	private ConsoleService consoleService;
	private AdvancedHookOptionsDialog advancedhookoptionsdialog;
	private Internal_structures_for_hook_generation internal_structures_for_hook_generation;
	
	public GenerateFridaHookScriptAction(PluginTool tool, String owner, Boolean isSnippet, Boolean isAdvanced)
	{
		super("Copy Frida Hook Script or Snippet", owner);
		this.incoming_plugintool = tool;
		this.isSnippet = isSnippet;
		this.isAdvanced = isAdvanced;
		

		/*Create the 3 submenus*/
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
		
		//Initialize the console
		this.consoleService=this.incoming_plugintool.getService(ConsoleService.class); //Note: If this line is called in the constructor, then the consoleService may be null
		//Next, initialize the dialog and the state for the hook generation
		this.internal_structures_for_hook_generation=new Internal_structures_for_hook_generation();
		this.advancedhookoptionsdialog = new AdvancedHookOptionsDialog("Advanced Frida Hook Options",this.incoming_plugintool,false);
		String hook_str="";
		
		
		Address addr;
		ProgramLocation location;
		Program current_program=context.getProgram();
		addr=context.getAddress();
		location = context.getLocation();
		/*Follow the location reference if it is present*/
		if (location instanceof OperandFieldLocation) {
			Address a = ((OperandFieldLocation) location).getRefAddress();
			if (a != null) {
				addr = a;
			}
		}
		System.out.println("Location:"+location);
		System.out.println("Program:"+current_program);
		System.out.println("Address:"+addr);
		
		if (this.isAdvanced)
		{
			System.gc(); //If advanced hooks are created many times, this may lead to a lot of memory being used
			this.advancedhookoptionsdialog.fetch_advanced_hook_options(addr, current_program);
			if (!this.advancedhookoptionsdialog.isOKpressed)
			{
				System.out.println("User clicked at advanced options but did not press OK");
				return;
			}
		}
		
		Function current_function = current_program.getFunctionManager().getFunctionContaining(addr);
		if (current_function==null && !this.isAdvanced)
		{
			//No advanced hooking, tried to hook address which is not in a function
			System.out.println("No hook generated, current function==NULL");
			Msg.showInfo(getClass(), context.getComponentProvider().getComponent(), "Hook generation error", "No hook generated, current function is NULL.");
			return;
		}
		

		if (this.isAdvanced && this.consoleService!=null)
		{
			this.consoleService.println("// Generating hooks... Please wait");
		}
		
		/*Create the task which will present a "Generating hooks..." message*/
		this.hook_generation_task=new Standard_hook_generation_task("Generating Hooks for address "+addr+"...",this.incoming_plugintool, current_program,addr, this.isAdvanced,this.isSnippet, 
				this.advancedhookoptionsdialog,this.internal_structures_for_hook_generation,this.consoleService,false); 
		this.incoming_plugintool.execute(this.hook_generation_task); //execute the task
		//Due to the way the task is constructed (modal = true, waitfortaskcompleted=true), the code will block here until the task is done.
		hook_str=hook_str.concat(this.hook_generation_task.result_of_standard_hook_generation); //The result is placed in advanced_hook_generation_task.result_of_advanced_hook_generation
				
		handle_output(hook_str); 
		
		//cleanup
		//Try to free as much memory as possible at the end
		this.internal_structures_for_hook_generation=null;
		this.advancedhookoptionsdialog=null;
		hook_str="";
		this.hook_generation_task=null;
		if (this.isAdvanced) {
			System.gc();
		}		
	}
	
	
	protected void handle_output(String hook_str)
	{
		Boolean user_has_cancelled_do_not_destroy_clipboard=false;
		if (this.isAdvanced && this.hook_generation_task.is_cancelled )
		{
			//This is the case where the user has manually cancelled
			hook_str="// User has cancelled\n";
			user_has_cancelled_do_not_destroy_clipboard=true;
		}
		if (this.isAdvanced && !this.hook_generation_task.is_cancelled )
		{
			if (this.consoleService!=null)
			{
				this.consoleService.println("// Hook Generated");
			}	
			hook_str=hook_str.concat("//Attempted to generate hooks for "+this.internal_structures_for_hook_generation.Addresses_for_current_hook_str.size()+" different addresses\n");
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
			this.consoleService.println(hook_str);
		}
		else
		{
			System.out.println("Can't print to console because consoleService is null");
		}
	}
	
}
