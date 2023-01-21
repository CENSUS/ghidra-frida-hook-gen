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

import ghidra.app.context.ListingActionContext;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskDialog;
import ghidra.util.task.TaskMonitor;

public class StandardHookGenerationTask extends Task {

	protected Boolean is_cancelled;
	private PluginTool incoming_plugintool;
	private Boolean isSnippet;
	private Boolean isAdvanced;
	protected String final_hook_str;
	Program incoming_program;
	Address incoming_address;
	private AdvancedHookOptionsDialog incoming_advancedhookoptionsdialog;
	protected InternalStructuresForHookGeneration internal_structures_for_hook_generation;
	private ConsoleService consoleService;
	private Boolean print_debug;
	protected String result_of_standard_hook_generation;
	
	public StandardHookGenerationTask(String title, PluginTool tool, Program incoming_program, Address incoming_address, Boolean isAdvanced, Boolean isSnippet, 
			AdvancedHookOptionsDialog incoming_advancedhookoptionsdialog,InternalStructuresForHookGeneration incoming_internal_structures,
			ConsoleService consoleService, Boolean print_debug) 
	{
		super(title,true,false,true,true);  //Modal, takes the screen , also waitForTaskCompleted=true	
		this.incoming_plugintool = tool;
		this.isSnippet = isSnippet;
		this.isAdvanced = isAdvanced;
		this.incoming_program=incoming_program;
		this.incoming_address=incoming_address;
		this.internal_structures_for_hook_generation=incoming_internal_structures;
		this.incoming_advancedhookoptionsdialog=incoming_advancedhookoptionsdialog;
		this.final_hook_str="";
		this.consoleService=consoleService;
		this.print_debug=print_debug;
		this.is_cancelled=false;
		this.result_of_standard_hook_generation="";
	}
	
	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		
		this.result_of_standard_hook_generation="";
		String hook_str="";
		//Initialize the hook generator. The variables we_are_in_the_first/last_hook_of_the_batch are set to true, as the generator will only be invoked once
		HookGenerator hook_generator=new HookGenerator(this.incoming_plugintool,this.incoming_program,this.incoming_address,this.isAdvanced,this.isSnippet,this.incoming_advancedhookoptionsdialog,
				monitor,this.internal_structures_for_hook_generation,true,true,this.consoleService,this.print_debug);
		
		monitor.checkCanceled();
		if (monitor.isCancelled())
		{
			this.is_cancelled=true;
			this.result_of_standard_hook_generation="";
			monitor.cancel();
			System.out.println("Task is cancelled");
			return;
		}
		
		
		hook_generator.do_generate_hook(); 
		
		if (monitor.isCancelled())
		{
			this.is_cancelled=true;
			this.result_of_standard_hook_generation="";
			monitor.cancel();
			System.out.println("Task is cancelled");
			return;
		}

		hook_str=hook_str.concat(hook_generator.final_hook_str);
		this.result_of_standard_hook_generation=hook_str; //put the result in result_of_standard_hook_generation
		System.out.println("Task is completed");
		return;
			
	}

}
