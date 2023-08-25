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

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;

import docking.action.KeyBindingType;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

public class SelectionHookGenerationTaskDispatcher {
	
	private PluginTool incoming_plugintool;
	private ArrayList<CodeUnit> incoming_selection;
	private ArrayList<CodeUnit> incoming_selection_to_exclude;
	private Program current_program;
	private Boolean is_invoked_with_a_created_advancedhookoptions_dialog;
	private AdvancedHookOptionsDialog once_off_advanced_hook_options_dialog;
	private ConsoleService consoleService;
	private InternalStructuresForHookGeneration internal_structures_for_hook_generation;
	private SelectionBatchHookGenerationTask selectionbatch_hook_generation_task;
	
	public SelectionHookGenerationTaskDispatcher(PluginTool plugintool, Program incoming_program,ArrayList<CodeUnit> selected_code_units_to_hook, ArrayList<CodeUnit> selected_code_units_to_exclude) {
		this.incoming_plugintool = plugintool;
		this.incoming_selection=selected_code_units_to_hook;
		this.incoming_selection_to_exclude=selected_code_units_to_exclude;
		this.current_program=incoming_program;
		this.is_invoked_with_a_created_advancedhookoptions_dialog=false;
	}
	
	public SelectionHookGenerationTaskDispatcher(PluginTool plugintool, Program incoming_program,ArrayList<CodeUnit> selected_code_units_to_hook,ArrayList<CodeUnit> selected_code_units_to_exclude, AdvancedHookOptionsDialog incoming_advancedhookoptionsdialog) {
		this.incoming_plugintool = plugintool;
		this.incoming_selection=selected_code_units_to_hook;
		this.incoming_selection_to_exclude=selected_code_units_to_exclude;
		this.current_program=incoming_program;
		this.is_invoked_with_a_created_advancedhookoptions_dialog=true;
		this.once_off_advanced_hook_options_dialog=incoming_advancedhookoptionsdialog;
	}

	

	public String perform_selection_hook_action()
	{
		String retval;
		ArrayList<CodeUnit> code_units_to_try_to_hook_into=this.incoming_selection; //these are the code units in the selection
		Listing current_program_listing=this.current_program.getListing();
		
		if (!is_invoked_with_a_created_advancedhookoptions_dialog)
		{
			/*Initialize the dialog, which will appear once and affect all the code units of the selection, one by one*/
			this.once_off_advanced_hook_options_dialog=new AdvancedHookOptionsDialog("Generate Hooks for selection",this.incoming_plugintool,this.current_program,true);
			this.once_off_advanced_hook_options_dialog.fetch_advanced_hook_options(null, this.current_program);  //show the dialog
		}
		else
		{
			/* The dialog is already initialized, make sure the values are set correctly*/
			this.once_off_advanced_hook_options_dialog.initDialogForAdvancedHookOptions(this.current_program, null);
			this.once_off_advanced_hook_options_dialog.okCallback();  //force the virtual pressing of the OK button
		}
		String entire_hook="";

		//Initialize the console
		this.consoleService=this.incoming_plugintool.getService(ConsoleService.class); 

		if (!this.once_off_advanced_hook_options_dialog.isOKpressed)
		{
			System.out.println("User clicked at advanced options but did not press OK");
			return "";
		}
		

		//use data structures that are common across all hook generation calls
		this.internal_structures_for_hook_generation=new InternalStructuresForHookGeneration();
		
		//put the addresses to be excluded inside the data structures (they are unique)
		for (int i=0;i<this.incoming_selection_to_exclude.size();i++)
		{
			Address tmpaddr=this.incoming_selection_to_exclude.get(i).getAddress();
			String in_place_of_hook=" //Address:"+tmpaddr+", explicitly excluded from hooking\n";
			String reason_for_hook_generation="Explicitly excluded from hooking";
			//manual insertion for the address in the structures. This code effectively clones the main part of the function HookGeneratorUtils::update_internal_data_structures() . TODO: do not repeat code 
			this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch++;
			String tmpstr=String.valueOf(this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch)+"|"+reason_for_hook_generation;
			this.internal_structures_for_hook_generation.Addresses_for_current_hook_str.put(tmpaddr.toString(),tmpstr); //this is the initial placement of this address in the Addresses_for_current_hook_str data structure
			this.internal_structures_for_hook_generation.addresses_for_which_hook_is_generated_in_order_of_appearance.add(tmpaddr);
			this.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.add(in_place_of_hook);
		}
		
		if (this.consoleService!=null)
		{
			this.consoleService.println("// Generating hooks... Please wait");
		}

		//Initialize the task which will do the job. It will present a "Generating hooks..." window
		this.selectionbatch_hook_generation_task=new SelectionBatchHookGenerationTask("Generating Hooks for selection...",code_units_to_try_to_hook_into,this.incoming_plugintool,this.current_program, 
													   this.once_off_advanced_hook_options_dialog,this.internal_structures_for_hook_generation,this.consoleService,false);
		this.incoming_plugintool.execute(selectionbatch_hook_generation_task); //Execute the task
		//Due to the way the task is constructed (modal = true, waitfortaskcompleted=true), the code will block here until the task is done.
		entire_hook=entire_hook.concat(this.selectionbatch_hook_generation_task.result_of_selectionbatch_hook_generation_task);  //the result is put in result_of_selectionbatch_hook_generation_task

		/*Output*/
		retval=handle_output(entire_hook,code_units_to_try_to_hook_into);

		//Try to cleanup
		code_units_to_try_to_hook_into=null;
		this.once_off_advanced_hook_options_dialog=null;
		this.selectionbatch_hook_generation_task=null;
		this.internal_structures_for_hook_generation=null;
		entire_hook="";
		System.gc();
		
		return retval;
	}
	

	
	protected String handle_output(String hook_str,ArrayList<CodeUnit> code_units_to_try_to_hook_into)
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
		
		//Print to Ghidra Console, but do not print if it is invoked through the GhidraScript with a created AdvancedHookOptionsDialog. 
		//In that case, the hook string will be returned to the user. 
		if (this.consoleService!=null && (!this.is_invoked_with_a_created_advancedhookoptions_dialog))
		{
			this.consoleService.println(hook_str);
		}
		else
		{
			System.out.println("Can't print to console because consoleService is null");
		}
		return hook_str;
	}
	
	
}
