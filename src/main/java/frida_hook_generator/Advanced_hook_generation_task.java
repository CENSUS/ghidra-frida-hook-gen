package frida_hook_generator;

import frida_hook_generator.frida_hook_generatorPlugin.GenerateFridaHookScriptAction;
import ghidra.app.context.ListingActionContext;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskDialog;
import ghidra.util.task.TaskMonitor;

public class Advanced_hook_generation_task extends Task {

	protected volatile Boolean is_cancelled;
	protected volatile Boolean is_hookgen_completed; 
	protected volatile Boolean is_backpatching_completed;
	private Boolean is_backpatching_needed;
	private PluginTool tool;
	private GenerateFridaHookScriptAction handler_to_incoming_hookscriptaction;
	private ListingActionContext incoming_context;
	private Address incoming_addr;
	private Boolean print_debug;
	
	public Advanced_hook_generation_task(String title, PluginTool tool, GenerateFridaHookScriptAction incoming_handler_to_frida_hook_script_action,ListingActionContext context, Address addr, Boolean print_debug)
	{
		super(title,true,false,true,true);  //Modal, takes the screen , also waitForTaskCompleted=true
		this.is_cancelled=false;
		this.is_hookgen_completed=false;
		this.is_backpatching_needed=incoming_handler_to_frida_hook_script_action.advancedhookoptionsdialog.isOutputReasonForHookGenCheckboxchecked;
		this.is_backpatching_completed=false;
		this.tool=tool;	
		this.handler_to_incoming_hookscriptaction=incoming_handler_to_frida_hook_script_action;
		this.incoming_context=context;
		this.incoming_addr=addr;
		this.print_debug=print_debug;
	}
	
	/* A simple function that basically calls the handle_advanced_hook_generation().*/
	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		
		String result_of_advanced_hook_generation="";
		
		monitor.checkCanceled();
		this.handler_to_incoming_hookscriptaction.incoming_monitor=monitor;
		if (monitor.isCancelled())
		{
			this.is_cancelled=true;
			this.handler_to_incoming_hookscriptaction.result_of_advanced_hook_generation="";
			monitor.cancel();
			System.out.println("Task is cancelled");
			return;
		}
		
		
		result_of_advanced_hook_generation=result_of_advanced_hook_generation.concat(this.handler_to_incoming_hookscriptaction.handle_advanced_hook_generation(this.incoming_context,this.incoming_addr,this.print_debug));
		if (this.is_cancelled)
		{
			this.handler_to_incoming_hookscriptaction.result_of_advanced_hook_generation="";
			monitor.cancel();
			System.out.println("Task is cancelled");
			return;
		}
		if (this.is_backpatching_needed)
		{
			result_of_advanced_hook_generation=result_of_advanced_hook_generation.concat(this.handler_to_incoming_hookscriptaction.backpatch_reasons_for_advanced_hook_generation());
			if (this.is_cancelled)
			{
				this.handler_to_incoming_hookscriptaction.result_of_advanced_hook_generation="";
				monitor.cancel();
				System.out.println("Task is cancelled");
				return;
			}
		}

		this.handler_to_incoming_hookscriptaction.result_of_advanced_hook_generation=result_of_advanced_hook_generation;
		System.out.println("Task is completed");
		return;
			
	}

}
