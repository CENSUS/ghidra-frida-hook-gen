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

import java.util.ArrayList;
import java.util.Iterator;

import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class SelectionBatch_hook_generation_task extends Task {


	protected Boolean is_cancelled;
	private ArrayList<CodeUnit> code_units_to_try_to_hook_into;
	private PluginTool incoming_plugintool;
	private Boolean isSnippet;
	private Boolean isAdvanced;
	protected String final_hook_str;
	Program incoming_program;
	private AdvancedHookOptionsDialog incoming_advancedhookoptionsdialog;
	protected Internal_structures_for_hook_generation internal_structures_for_hook_generation;
	private ConsoleService consoleService;
	private Boolean print_debug;
	protected String result_of_selectionbatch_hook_generation_task;
	
	public SelectionBatch_hook_generation_task(String title, ArrayList<CodeUnit> code_units_to_try_to_hook_into, PluginTool tool, Program incoming_program, 
											   AdvancedHookOptionsDialog incoming_advancedhookoptionsdialog,Internal_structures_for_hook_generation incoming_internal_structures,
											   ConsoleService consoleService, Boolean print_debug)
	{
		super(title,true,false,true,true);  //Modal, takes the screen , also waitForTaskCompleted=true
		this.incoming_advancedhookoptionsdialog=incoming_advancedhookoptionsdialog;
		this.isSnippet=!this.incoming_advancedhookoptionsdialog.isGenerateScriptCheckboxchecked;
		this.isAdvanced=true;  //this is always an Advanced hook
		this.is_cancelled=false;
		this.incoming_program=incoming_program;
		this.internal_structures_for_hook_generation=incoming_internal_structures;
		this.final_hook_str="";
		this.consoleService=consoleService;
		this.print_debug=print_debug;
		this.code_units_to_try_to_hook_into=code_units_to_try_to_hook_into;
		this.incoming_plugintool=tool;
		this.print_debug=print_debug;
		this.result_of_selectionbatch_hook_generation_task="";
	}
	
	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		
		String hook_str="";
		this.result_of_selectionbatch_hook_generation_task="";
		
		monitor.checkCanceled();
		if (monitor.isCancelled())
		{
			this.is_cancelled=true;
			this.result_of_selectionbatch_hook_generation_task="";
			monitor.cancel();
			System.out.println("Task is cancelled");
			return;
		}
		
		Boolean we_are_in_the_final_hook_of_the_batch=false;
		Boolean we_are_in_the_first_hook_of_the_batch=false;
		
		/*We will run multiple invocations of the Hook Generator, but these will share the internal data structures, and the end result will appear as one large invocation*/
		for (int i=0;i<code_units_to_try_to_hook_into.size();i++)
		{
			CodeUnit current_code_unit=this.code_units_to_try_to_hook_into.get(i);
			Address current_address=current_code_unit.getAddress();
			if (i==0)
			{
				//In case of script creation, which needs prologue/epilogue
				we_are_in_the_first_hook_of_the_batch=true;
			}
			else
			{
				we_are_in_the_first_hook_of_the_batch=false;
			}
			
			if (i==code_units_to_try_to_hook_into.size()-1)
			{
				//Backpatching of reasons should only be done in the last time. Also, in case of script creation, which needs prologue/epilogue
				we_are_in_the_final_hook_of_the_batch=true;
			}
			/*Initialize and run the hook generator for this iteration of the loop*/
			Hook_generator hook_generator=new Hook_generator(this.incoming_plugintool,this.incoming_program,current_address,this.isAdvanced,this.isSnippet,this.incoming_advancedhookoptionsdialog,
					monitor,this.internal_structures_for_hook_generation,we_are_in_the_first_hook_of_the_batch,we_are_in_the_final_hook_of_the_batch,this.consoleService,this.print_debug);
			hook_generator.do_generate_hook();
			if (monitor.isCancelled()) //check for cancellation
			{
				this.is_cancelled=true;
				this.result_of_selectionbatch_hook_generation_task="";
				monitor.cancel();
				System.out.println("Task is cancelled");
				return;
			}
			hook_str=hook_str.concat(hook_generator.final_hook_str); //If not, append the output
		}

		if (monitor.isCancelled())
		{
			this.is_cancelled=true;
			this.result_of_selectionbatch_hook_generation_task="";
			monitor.cancel();
			System.out.println("Task is cancelled");
			return;
		}


		this.result_of_selectionbatch_hook_generation_task=hook_str; //Set the result
		System.out.println("Task is completed");
		return;
			
	}


}
