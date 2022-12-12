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

import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Objects;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingType;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.symboltree.SymbolTreeActionContext;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.table.GhidraTable;

public class Selection_hook_generationAction extends DockingAction {
	protected Plugin incoming_plugin;
	protected ProgramSelection incoming_selection;
	protected Program current_program;
	private AdvancedHookOptionsDialog once_off_advanced_hook_options_dialog;
	private ConsoleService consoleService;
	private Internal_structures_for_hook_generation internal_structures_for_hook_generation;
	private SelectionBatch_hook_generation_task selectionbatch_hook_generation_task;
	
	public Selection_hook_generationAction(Plugin plugin, ProgramSelection current_selection) {
		super("Create_frida_hook_for_selection", plugin.getName(), KeyBindingType.SHARED);
		this.incoming_plugin = plugin;
		this.incoming_selection=current_selection; //will be null initially
		this.current_program=null;
		init();
	}
	
	private void init() {
		setPopupMenuData(
			new MenuData(new String[] { "Create Frida Hooks for selection..." }, null,"Frida-Hook"));
		setDescription("Generate Frida Hooks from the selected rows");
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		/*This function not only checks if the submenu should appear (be enabled), 
		 * it also initializes the variable it's based on, the "this.current_program"
		 */
		
		if (this.incoming_plugin==null)
		{
			return false;
		}
				
		/* The first allowed case, when we are invoked from a "Search..." menu, our ContextObject is a Ghidra Table*/
		if (context.getContextObject() instanceof GhidraTable)
		{
			this.current_program=((GhidraTable)context.getContextObject()).getProgram();
			if (this.current_program==null)
			{
				return false;
			}
		}
		
		/*The second allowed case, if we are in a ProgramActionContext. The ListingActionContext, in the typical (non-selection) invocation of the plugin, is a subclass of that*/
		if (context instanceof ProgramActionContext)
		{
			this.current_program=((ProgramActionContext) context).getProgram();
			if (this.current_program==null)
			{
				return false;
			}
		}
		
		if (this.current_program==null)
		{
			return false;
		}

		this.incoming_selection=((ProgramPlugin)incoming_plugin).getProgramSelection();  //The creator is a frida_hook_generatorPlugin, therefore a ProgramPlugin
		return (this.incoming_selection!=null && incoming_selection.getNumAddresses()>0);
	}
	
	
	@Override
	public void actionPerformed(ActionContext context) {

		ArrayList<CodeUnit> code_units_to_try_to_hook_into=new ArrayList<CodeUnit>(); //these are the code units in the selection
		Listing current_program_listing=this.current_program.getListing();
		/*Initialize the dialog, which will appear once and affect all the code units of the selection, one by one*/
		this.once_off_advanced_hook_options_dialog=new AdvancedHookOptionsDialog("Generate Hooks for selection",this.incoming_plugin.getTool(),this.current_program,true);
		this.once_off_advanced_hook_options_dialog.fetch_advanced_hook_options(null, this.current_program);  //show the dialog
		String entire_hook="";

		//Initialize the console
		this.consoleService=this.incoming_plugin.getTool().getService(ConsoleService.class); //Note: If this line is called in the constructor, then the consoleService may be null

		if (!this.once_off_advanced_hook_options_dialog.isOKpressed)
		{
			System.out.println("User clicked at advanced options but did not press OK");
			return;
		}
		
		
		Iterator<Address> address_iterator= this.incoming_selection.getAddresses(true);
		/* Get all the code units */
		System.out.println("Getting all the code units for the selected addresses...");
		while (address_iterator!=null && address_iterator.hasNext())
		{
			Address current_address=address_iterator.next();
			CodeUnit current_code_unit=current_program_listing.getCodeUnitAt(current_address); //Is the current address at the start of a code unit?
			if (current_code_unit!=null)
			{
				code_units_to_try_to_hook_into.add(current_code_unit); //If yes, add it to the list
			}
		}
		
		//use data structures that are common across all hook generation calls
		this.internal_structures_for_hook_generation=new Internal_structures_for_hook_generation();
		
		
		if (this.consoleService!=null)
		{
			this.consoleService.println("// Generating hooks... Please wait");
		}

		//Initialize the task which will do the job. It will present a "Generating hooks..." window
		this.selectionbatch_hook_generation_task=new SelectionBatch_hook_generation_task("Generating Hooks for selection...",code_units_to_try_to_hook_into,this.incoming_plugin.getTool(),this.current_program, 
													   this.once_off_advanced_hook_options_dialog,this.internal_structures_for_hook_generation,this.consoleService,false);
		this.incoming_plugin.getTool().execute(selectionbatch_hook_generation_task); //Execute the task
		//Due to the way the task is constructed (modal = true, waitfortaskcompleted=true), the code will block here until the task is done.
		entire_hook=entire_hook.concat(this.selectionbatch_hook_generation_task.result_of_selectionbatch_hook_generation_task);  //the result is put in result_of_selectionbatch_hook_generation_task

		/*Output*/
		handle_output(entire_hook,code_units_to_try_to_hook_into);

		//Try to cleanup
		code_units_to_try_to_hook_into=null;
		address_iterator=null;
		this.once_off_advanced_hook_options_dialog=null;
		this.selectionbatch_hook_generation_task=null;
		this.internal_structures_for_hook_generation=null;
		entire_hook="";
		System.gc();
	}
	
	

	
	protected void handle_output(String hook_str,ArrayList<CodeUnit> code_units_to_try_to_hook_into)
	{
		Boolean user_has_cancelled_do_not_destroy_clipboard=false;
		if (this.selectionbatch_hook_generation_task.is_cancelled )
		{
			//This is the case where the user has manually cancelled
			hook_str="// User has cancelled\n";
			user_has_cancelled_do_not_destroy_clipboard=true;
		}
		else
		{
			if (this.consoleService!=null)
			{
				this.consoleService.println("// Hook Generated");
			}	
			hook_str=hook_str.concat("// Tried to generate hooks for "+this.internal_structures_for_hook_generation.Addresses_for_current_hook_str.size()+" different addresses, coming from a selection size of "+code_units_to_try_to_hook_into.size()+" code units\n");
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
