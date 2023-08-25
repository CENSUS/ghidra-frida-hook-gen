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

public class SelectionHookGenerationAction extends DockingAction {
	protected Plugin incoming_plugin;
	protected ProgramSelection incoming_selection;
	protected Program current_program;
	private SelectionHookGenerationTaskDispatcher selection_hook_generation_dispatcher;

	
	public SelectionHookGenerationAction(Plugin plugin, ProgramSelection current_selection) {
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
		
		ArrayList<CodeUnit> code_units_to_try_to_hook_into=new ArrayList<CodeUnit>(); //these will be the code units in the selection

		Listing current_program_listing=this.current_program.getListing();

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
		
		this.selection_hook_generation_dispatcher=new SelectionHookGenerationTaskDispatcher(this.incoming_plugin.getTool(),this.current_program,code_units_to_try_to_hook_into,new ArrayList<CodeUnit>());
		this.selection_hook_generation_dispatcher.perform_selection_hook_action();
	}
	
	

}
