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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.regex.Pattern;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class HookGenerator {

	protected PluginTool incoming_plugintool;
	protected Boolean isSnippet;
	protected Boolean isAdvanced;
	protected String final_hook_str;
	Program incoming_program;
	Address incoming_address;
	protected AdvancedHookOptionsDialog incoming_advancedhookoptionsdialog;
	protected Boolean we_are_in_the_first_hook_of_the_batch;
	protected Boolean we_are_in_the_final_hook_of_the_batch;
	protected InternalStructuresForHookGeneration internal_structures_for_hook_generation;
	protected ConsoleService consoleService;
	protected TaskMonitor incoming_monitor;
	protected Boolean print_debug;
	
	protected Boolean include_onEnter_in_function_hooks;
	protected Boolean include_onLeave_in_function_hooks;
	protected Boolean use_interceptor_attach_instead_of_replace_in_function_hooks;
	
	protected Program current_program; 
	protected String current_program_name;
	protected String current_program_name_sanitized;
	protected Listing current_program_listing;
	protected Language current_program_language;
	protected Address image_base;
	protected Processor current_program_processor;
	protected String characters_allowed_in_variable_name="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
	protected AdvancedHookOptionsDialog advancedhookoptionsdialog;
	protected int maximum_number_of_reasons_to_show=0;
	protected HookGeneratorUtils utils;
	protected String generated_hook_for_imported_functions=""; //this variable is populated in case the relevant option for imported function hooking is enabled

	
	
	public HookGenerator(PluginTool tool, Program incoming_program, Address incoming_address, Boolean isAdvanced, Boolean isSnippet, AdvancedHookOptionsDialog incoming_advancedhookoptionsdialog,
			TaskMonitor incoming_taskmonitor,InternalStructuresForHookGeneration incoming_internal_structures, Boolean we_are_in_the_first_hook_of_the_batch,Boolean we_are_in_the_final_hook_of_the_batch,
			ConsoleService consoleService,Boolean print_debug)
	{
		this.incoming_plugintool = tool;
		this.isSnippet = isSnippet;
		this.isAdvanced = isAdvanced;
		this.incoming_program=incoming_program;
		this.incoming_address=incoming_address;
		this.internal_structures_for_hook_generation=incoming_internal_structures;
		this.incoming_monitor=incoming_taskmonitor;
		this.incoming_advancedhookoptionsdialog=incoming_advancedhookoptionsdialog;
		this.final_hook_str="";
		this.we_are_in_the_final_hook_of_the_batch=we_are_in_the_final_hook_of_the_batch;
		this.we_are_in_the_first_hook_of_the_batch=we_are_in_the_first_hook_of_the_batch;
		this.consoleService=consoleService;
		this.print_debug=print_debug;
		this.utils=new HookGeneratorUtils(this);
	}
	

	protected void do_generate_hook() {
		
		this.include_onEnter_in_function_hooks=true;
		this.include_onLeave_in_function_hooks=true;
		this.use_interceptor_attach_instead_of_replace_in_function_hooks=true;
		
		if (this.isAdvanced)
		{
			this.advancedhookoptionsdialog=this.incoming_advancedhookoptionsdialog;
		}
		
		Address addr=this.incoming_address;
		this.current_program=this.incoming_program;
		
		
		if (this.isAdvanced)
		{
			//Set up the boolean variables affecting the function hook generation
			this.utils.interpret_user_custom_options_on_function_hook_generation();
		}
		
		/* Initialize some other useful things*/
		this.current_program_name = this.current_program.getName();
		Function current_function = this.current_program.getFunctionManager().getFunctionContaining(addr);
		this.current_program_listing = this.current_program.getListing();
		this.current_program_name_sanitized = this.current_program_name.replaceAll("[^"+this.characters_allowed_in_variable_name+"]", "_");
		this.image_base = this.current_program.getImageBase();
		this.current_program_language = this.current_program.getLanguage();
		this.current_program_processor = this.current_program_language.getProcessor();


		//Begin creating the hook
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
		if (!this.isSnippet && this.we_are_in_the_first_hook_of_the_batch)
		{
			hook_str+=this.utils.generate_prologue_for_address(addr,true);
		}
		
		//handle the simple right click case
		if (!this.isAdvanced)
		{
			handle_simple_right_click_hook_generation(addr,true);
		}
		//handle all Advanced cases
		if (this.isAdvanced)
		{
			handle_advanced_hook_generation(addr,false);
		}
		
		if (this.we_are_in_the_final_hook_of_the_batch && !this.incoming_monitor.isCancelled())
		{
			if (this.isAdvanced && this.advancedhookoptionsdialog.isHookImportsCheckBoxchecked)
			{
				hook_str+=this.generated_hook_for_imported_functions;  //this is a quick and dirty way, TODO: put the hooks in place using the internal data structures
			}
			if (this.isAdvanced && this.advancedhookoptionsdialog.isOutputReasonForHookGenCheckboxchecked)
			{
				this.utils.backpatch_reasons_for_advanced_hook_generation(); //this will update the reasons in the individual hooks
			}
			if (this.isAdvanced && !this.incoming_monitor.isCancelled() && this.utils.is_there_a_chance_that_some_hooks_generated_in_the_current_batch_require_code_that_is_later_added_in_the_hook())
			{
				this.utils.backpatch_hooks_that_need_code_to_be_added_at_a_later_stage(); //this will update the hooks that may need further additions to their code. Note: This should happen in any case that there is a chance that one address had such a hook, as placeholders will have been put. In other words, if any of the related advanced options is selected, call this function
			}
			if (!this.incoming_monitor.isCancelled())
			{
				hook_str=hook_str.concat(gather_all_generated_hooks());
			}
		}
		
		

		//Now, the epilogue
		if (!this.isSnippet && this.we_are_in_the_final_hook_of_the_batch && !this.incoming_monitor.isCancelled())
		{
			hook_str+=this.utils.generate_epilogue_for_address(addr,true);
		}
		
		handle_output(hook_str);
		
	
	}
	
	
	

	protected void handle_output(String hook_str)
	{
		if (this.incoming_monitor!=null && this.incoming_monitor.isCancelled() )
		{
			//This is the case where the user has manually cancelled
			hook_str="// User has cancelled\n";
		}
		this.final_hook_str=hook_str;  //Simply set the this.final_hook_str, the caller classes will take care of outputting to the user
	}
	
	
	
	
	
	
	protected void handle_simple_right_click_hook_generation(Address addr, Boolean print_debug)
	{
		generate_snippet_hook_for_address(addr,print_debug,"Simple Right Click");
	}
	
	
	
	
	/* This is a big and complex function, handling all sub-cases for the advanced hook generation*/
	protected void handle_advanced_hook_generation(Address addr, Boolean print_debug)
	{
		Function current_function = this.current_program.getFunctionManager().getFunctionContaining(addr);

		if (this.incoming_monitor.isCancelled()) {return ;} //check for cancellation by the user
		this.incoming_monitor.setMessage("Generating Hooks...");
		
		
		/*References to address*/
		if (this.advancedhookoptionsdialog.isReferencestoAddressCheckBoxchecked || this.advancedhookoptionsdialog.isFunctionsReferencingAddressCheckBoxchecked)
		{
			CodeUnit current_codeunit=this.current_program_listing.getCodeUnitAt(addr);
			Instruction current_instruction=this.current_program_listing.getInstructionAt(addr); //The current address may not be in code, careful
			if (current_codeunit!=null)
			{
				ReferenceIterator ref_iter= current_codeunit.getReferenceIteratorTo();
				while(ref_iter.hasNext())
				{
					Reference ref = ref_iter.next();
					Address newaddr=ref.getFromAddress();
					if (this.advancedhookoptionsdialog.isReferencestoAddressCheckBoxchecked)
					{
						generate_snippet_hook_for_address(newaddr,true,"Address referencing address "+addr+" , referenceType:"+ref.getReferenceType());
					}
					if (this.advancedhookoptionsdialog.isFunctionsReferencingAddressCheckBoxchecked)
					{
						Function newfun=this.current_program.getFunctionManager().getFunctionContaining(newaddr);
						if (newfun!=null)
						{
							generate_snippet_hook_for_address(newfun.getEntryPoint(),true,"Function containing address "+newaddr+" that references to initial address "+addr+" through referenceType:"+ref.getReferenceType());
					
						}	
					}
				}					
			}
		}
		
		if (this.incoming_monitor.isCancelled()) { return;} //check for cancellation by the user

		
		/*References to function*/
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
					generate_snippet_hook_for_address(newaddr,true,"Address referencing function at "+current_function.getEntryPoint()+" named "+current_function.getName(true).replace("\"", "_")+" containing address "+addr+", through referenceType:"+ref.getReferenceType());
				}
			}
			
		}
		
		if (this.incoming_monitor.isCancelled()) { return;} //check for cancellation by the user
	
		/*Incoming references, for a certain depth*/
		if (this.advancedhookoptionsdialog.isFunctionsReferencingFunctionCheckboxchecked && current_function!=null)
		{
			int i;
			int j;
			int depth=Integer.parseInt(this.advancedhookoptionsdialog.InFunctionReferenceDepthcomboBox.getItemAt(this.advancedhookoptionsdialog.InFunctionReferenceDepthcomboBox.getSelectedIndex()));
			
			/*
			 * Complex data type, the external ArrayList holds items for each depth level, and the internal ArrayList contains Functions for a specific depth, accompanied by helper values (all in a Container) . This entire data structure serves the purpose of keeping track of the reference arrows (who has called who), in order to follow them backwards
			 * At position all_depths_arraylists_of_function_references.get(i).get(j), the j'th caller Function for depth 'i' is held. (The j'th as returned by a set iterator, not necessarily being at the j'th position in the code).
			 */
			ArrayList<ArrayList<ContainerForFunctionReferences>> all_depths_arraylists_of_function_references=new ArrayList<ArrayList<ContainerForFunctionReferences>>();

			//initially for level 0
			ArrayList<ContainerForFunctionReferences> arraylist_for_level_i=new ArrayList<ContainerForFunctionReferences>();
			arraylist_for_level_i.add(new ContainerForFunctionReferences(current_function,-1,-1,0));
			all_depths_arraylists_of_function_references.add((ArrayList<ContainerForFunctionReferences>) arraylist_for_level_i.clone());
			

			for (i=1;i<=depth;i++)
			{
				this.incoming_monitor.setMessage("Incoming references, level "+i);
				
				arraylist_for_level_i=this.utils.handle_incoming_references_for_one_depth_level((ArrayList<ContainerForFunctionReferences>) arraylist_for_level_i.clone(),i);
				all_depths_arraylists_of_function_references.add((ArrayList<ContainerForFunctionReferences>) arraylist_for_level_i.clone());
				for (j=0;j<arraylist_for_level_i.size();j++)
				{
					Function newfun=arraylist_for_level_i.get(j).fun;
					String reference_path_string=this.utils.get_incoming_reference_path_string(all_depths_arraylists_of_function_references,i,j);
					generate_snippet_hook_for_address(newfun.getEntryPoint(),false,"Incoming function call reference from function at "+newfun.getEntryPoint()+" named "+newfun.getName(true).replace("\"", "_")+", to final current function "+current_function.getName(true).replace("\"", "_")+" containing address "+addr+", after call depth="+i+", using call path:"+reference_path_string);
				
					if (j%100==0 && this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
				}
				if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
			}
			
		}
		
		/*Outgoing references, for a certain depth*/
		if (this.advancedhookoptionsdialog.isOutReferencesfromFunctionCheckBoxchecked && current_function!=null)
		{
			int i;
			int j;
			int depth=Integer.parseInt(this.advancedhookoptionsdialog.OutFunctionReferenceDepthcomboBox.getItemAt(this.advancedhookoptionsdialog.OutFunctionReferenceDepthcomboBox.getSelectedIndex()));
			
			/*
			 * Complex data type, the external ArrayList holds items for each depth level, and the internal ArrayList contains Functions for a specific depth, accompanied by helper values (all in a Container) . This entire data structure serves the purpose of keeping track of the reference arrows (who has called who), in order to follow them backwards
			 * At position all_depths_arraylists_of_function_references.get(i).get(j), the j'th called Function for depth 'i' is held. (The j'th as returned by a set iterator, not necessarily being at the j'th position in the code).
			 */				
			ArrayList<ArrayList<ContainerForFunctionReferences>> all_depths_arraylists_of_function_references=new ArrayList<ArrayList<ContainerForFunctionReferences>>();

			//initially for level 0
			ArrayList<ContainerForFunctionReferences> arraylist_for_level_i=new ArrayList<ContainerForFunctionReferences>();
			arraylist_for_level_i.add(new ContainerForFunctionReferences(current_function,-1,-1,0));
			all_depths_arraylists_of_function_references.add((ArrayList<ContainerForFunctionReferences>) arraylist_for_level_i.clone());
							
			for (i=1;i<=depth;i++)
			{
				this.incoming_monitor.setMessage("Outgoing calls, level "+i);
				arraylist_for_level_i=this.utils.handle_outgoing_references_for_one_depth_level((ArrayList<ContainerForFunctionReferences>) arraylist_for_level_i.clone(),i);
				all_depths_arraylists_of_function_references.add((ArrayList<ContainerForFunctionReferences>) arraylist_for_level_i.clone());
				for (j=0;j<arraylist_for_level_i.size();j++)
				{
					Function newfun=arraylist_for_level_i.get(j).fun;
					String reference_path_string=this.utils.get_outgoing_reference_path_string(all_depths_arraylists_of_function_references,i,j);
					generate_snippet_hook_for_address(newfun.getEntryPoint(),false,"Outgoing function call reference to function at "+newfun.getEntryPoint()+" named "+newfun.getName(true).replace("\"", "_")+", from initial current function "+current_function.getName(true).replace("\"", "_")+" containing address "+addr+", after call depth="+i+", using call path:"+reference_path_string);
					
					if (j%100==0 && this.incoming_monitor.isCancelled()) { return;} //check for cancellation by the user
				}
				if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
			}
			
		}
		
		if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
		
		
		if (this.advancedhookoptionsdialog.isOutReferencesfromAddressCheckBoxchecked)
		{
			CodeUnit current_codeunit=this.current_program_listing.getCodeUnitAt(addr);
			Instruction current_instruction=this.current_program_listing.getInstructionAt(addr); //The current address may not be in code, careful
			if (current_codeunit!=null)
			{
				Reference[] references= current_codeunit.getReferencesFrom();
				for (int i=0;i<references.length;i++)
				{
					Reference ref = references[i];
					Address newaddr=ref.getToAddress();
					generate_snippet_hook_for_address(newaddr,true,"Address referenced from address "+addr+" , referenceType:"+ref.getReferenceType());
				}					
			}
		}
		
		if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
		
		if (this.advancedhookoptionsdialog.isOutDynamicCallReferencesfromFunctionCheckBoxchecked && current_function!=null)
		{
			this.incoming_monitor.setMessage("Dynamic calls for function...");
			AddressIterator all_addresses_in_this_function=current_function.getBody().getAddresses(true);
			int addresses_processed=0;
			
			while (all_addresses_in_this_function.hasNext())
			{
				Address newaddr=all_addresses_in_this_function.next();
				Instruction newinstr=this.current_program_listing.getInstructionAt(newaddr);
				String reason_for_hook="Address "+newaddr+" containing a dynamic (computed) call/jump";
				if (newinstr!=null && this.utils.does_the_current_instruction_definitely_need_hook_code_to_also_be_added_later(newinstr,reason_for_hook))
				{	
					generate_snippet_hook_for_address(newaddr,true,reason_for_hook);		//Careful: This particular reason is used to check if internal data structures should be updated. If changed, update the  update_internal_data_structures()/does_the_current_instruction_definitely_need_hook_code_to_also_be_added_later() function		
				}
				
				if (addresses_processed%200==0 && this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
				addresses_processed++;
			}

		}
		
		if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
		
		
		/*Hook this address checkbox*/
		if (this.advancedhookoptionsdialog.isHookThisAddressCheckBoxchecked)
		{
			this.incoming_monitor.setMessage("Hooking this address...");
			
			generate_snippet_hook_for_address(addr,true,"Asked to hook the current (selected) address, which was used to spawn the dialog");
		}
		
		if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user

		
		/* Range hooking, for addresses */
		// TODO: see if this can be done faster, perhaps by iterating over instructions only. Careful with the function endings
		if (this.advancedhookoptionsdialog.isRangeAddressesCheckBoxchecked && this.advancedhookoptionsdialog.RangeAddressesNum>0)
		{
			long max_address=this.current_program.getMaxAddress().getOffset();  //this does not work, keeping it here for future reference 
			long initial_addr_offset=addr.getOffset();
			long curraddr_offset=initial_addr_offset;
			int num_of_addresses_advanced=0;
			int num_of_instructions_advanced=0;
			int num_of_functions_advanced=0;
			int number_of_times_iterated=0;
			
			if (print_debug)
			{
				System.out.println("RangeAddressesNum: "+this.advancedhookoptionsdialog.RangeAddressesNum);
			}

			this.incoming_monitor.setMessage("Range for addresses...");
			
			CodeUnitIterator code_unit_iterator=this.current_program_listing.getCodeUnits(addr, true);

			if (code_unit_iterator!=null)
			{
				while (code_unit_iterator.hasNext())
				{
					CodeUnit newcodeunit=code_unit_iterator.next();
					Address newaddr=newcodeunit.getAddress();
					Boolean we_are_at_the_first_byte_of_an_instruction=false;
					Boolean we_have_reached_the_maxaddress_of_a_function=false;
					number_of_times_iterated++;
					
					/*
					 * A function may have its MaxAddress on something other than an instruction.
					 * Also, very important: The MaxAddress seems to be the last byte of the last code unit, not the start of the last code unit
					 */
					Function newfun = this.current_program.getFunctionManager().getFunctionContaining(newaddr);
					if (newfun!=null &&  this.current_program_listing.getCodeUnitContaining(newfun.getBody().getMaxAddress()).equals(newcodeunit)) //function has ended
					{
						we_have_reached_the_maxaddress_of_a_function=true;
					}
					
					Instruction newinstr=current_program_listing.getInstructionAt(newaddr);	
					if (newinstr!=null) 
					{
						we_are_at_the_first_byte_of_an_instruction=true;
					}
					

					
					if (we_have_reached_the_maxaddress_of_a_function)
					{
						//increase the function counter
						num_of_functions_advanced++;
					}
					if (we_are_at_the_first_byte_of_an_instruction)
					{
						//Increase the instruction counter
						num_of_instructions_advanced++;
					}
					
					//Increase the address counters
					curraddr_offset=newaddr.getOffset()-initial_addr_offset;
					num_of_addresses_advanced=(int) (newaddr.getOffset()-initial_addr_offset);
					
					
					/* Careful: if we have exceeded the allowed addresses, break. Else, continue and hook.*/
					if (this.advancedhookoptionsdialog.RangeAddressesRadioButtonAddr.isSelected() && num_of_addresses_advanced>this.advancedhookoptionsdialog.RangeAddressesNum)
					{
						break;
					}
					
					if (we_are_at_the_first_byte_of_an_instruction)
					{
						//We can only hook instructions at their first byte
						generate_snippet_hook_for_address(newaddr,false,"Address hook in range of initial address "+addr+". Offset from that: "+num_of_addresses_advanced+" addresses, "+num_of_instructions_advanced+" instructions, "+num_of_functions_advanced+" functions.");
					}
					
					/*Now, the check is for >= , as both the instructions and the functions will always increase one by one*/
					if (this.advancedhookoptionsdialog.RangeAddressesRadioButtonFun.isSelected() && num_of_functions_advanced>=this.advancedhookoptionsdialog.RangeAddressesNum)
					{
						break;
					}
					if (this.advancedhookoptionsdialog.RangeAddressesRadioButtonInstr.isSelected() && num_of_instructions_advanced>=this.advancedhookoptionsdialog.RangeAddressesNum)
					{
						break;
					}

					if (number_of_times_iterated%100==0 && this.incoming_monitor.isCancelled()) { return;} //check for cancellation by the user
					if (number_of_times_iterated%2000==0) 
					{
						//update the "Generating hooks..." dialog
						if (this.advancedhookoptionsdialog.RangeAddressesRadioButtonAddr.isSelected()) {this.incoming_monitor.setMessage("Range for addresses "+num_of_addresses_advanced+"...");}
						if (this.advancedhookoptionsdialog.RangeAddressesRadioButtonInstr.isSelected()) {this.incoming_monitor.setMessage("Range for addresses "+num_of_instructions_advanced+"...");}
						if (this.advancedhookoptionsdialog.RangeAddressesRadioButtonFun.isSelected()) {this.incoming_monitor.setMessage("Range for addresses "+num_of_functions_advanced+"...");}
					}
				}
			}
		}
		
		
		/* Range hooking, for functions, only forward */
		if (this.advancedhookoptionsdialog.isRangeFunctionsCheckBoxchecked && this.advancedhookoptionsdialog.RangeFunctionsNum>0 && !this.advancedhookoptionsdialog.RangeFunctionsRadioButtonFunBackwards.isSelected())
		{
			//get all functions starting from this address
			FunctionIterator fun_iter=this.current_program_listing.getFunctions(addr, true);
			long initial_addr_offset=addr.getOffset();
			long curraddr_offset=initial_addr_offset;
			int num_of_addresses_advanced=0;
			//instructions will not be used as a counter, is there any way of using them, without iterating over all of the instructions? In other words, to get the number of instructions inside a function, without iterating over all of them.
			//int num_of_instructions_advanced=0;
			int num_of_functions_advanced=0;
			long offset_of_new_fun_end;
			long offset_of_new_fun_start;
			Boolean we_are_done_for_RangeFunctions=false;
			
			this.incoming_monitor.setMessage("Range for functions...");
			
			//if we are inside a function, we want to hook that one
			Function newfun = this.current_program.getFunctionManager().getFunctionContaining(addr);
			
			if (newfun!=null)
			{
				generate_snippet_hook_for_address(newfun.getEntryPoint(),false,"Function hook in range of initial address "+addr+". Offset from that: "+num_of_addresses_advanced+" addresses, "+num_of_functions_advanced+" functions.");
				num_of_functions_advanced++; //in this case, 1 function means -> hook the present one
				if (newfun.getEntryPoint().equals(addr))
				{
					//consume the first of the iterator if we are at the start of the first function.
					if (fun_iter.hasNext()) {fun_iter.next();};
				}
			}
			
			while (!we_are_done_for_RangeFunctions && fun_iter.hasNext())
			{
				newfun=fun_iter.next();
				offset_of_new_fun_end=newfun.getBody().getMaxAddress().getOffset();
				offset_of_new_fun_start=newfun.getEntryPoint().getOffset();
				num_of_addresses_advanced=(int) (offset_of_new_fun_start-initial_addr_offset);
				num_of_functions_advanced++;
				if (this.advancedhookoptionsdialog.RangeFunctionsRadioButtonAddr.isSelected() && num_of_addresses_advanced>this.advancedhookoptionsdialog.RangeFunctionsNum) 
				{
					we_are_done_for_RangeFunctions=true;
					break;
				}
				if (this.advancedhookoptionsdialog.RangeFunctionsRadioButtonFun.isSelected() && num_of_functions_advanced>this.advancedhookoptionsdialog.RangeFunctionsNum)
				{
					we_are_done_for_RangeFunctions=true;
					break;
				}
				generate_snippet_hook_for_address(newfun.getEntryPoint(),false,"Function hook in range of initial address "+addr+". Offset from that: "+num_of_addresses_advanced+" addresses, "+num_of_functions_advanced+" functions.");
			
				if (num_of_functions_advanced%100==0 && this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
				if (num_of_functions_advanced%1000==0) {this.incoming_monitor.setMessage("Range for functions "+num_of_functions_advanced+"...");}
			}

		}
		
		if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user

		
		/* Range hooking, for functions, only backwards */
		if (this.advancedhookoptionsdialog.isRangeFunctionsCheckBoxchecked && this.advancedhookoptionsdialog.RangeFunctionsNum>0 && this.advancedhookoptionsdialog.RangeFunctionsRadioButtonFunBackwards.isSelected())
		{
			//get all functions starting from this address, going backwards
			FunctionIterator fun_iter=this.current_program_listing.getFunctions(addr, false);
			long initial_addr_offset=addr.getOffset();
			long curraddr_offset=initial_addr_offset;
			int num_of_addresses_advanced=0;
			int num_of_functions_advanced=0;
			long offset_of_new_fun_end;
			long offset_of_new_fun_start;
			Boolean we_are_done_for_RangeFunctions=false;
			
			this.incoming_monitor.setMessage("Range for functions (backwards)...");
			
			//if we are inside a function, we want to hook that one
			Function newfun = this.current_program.getFunctionManager().getFunctionContaining(addr);
			
			if (newfun!=null)
			{
				generate_snippet_hook_for_address(newfun.getEntryPoint(),false,"Function hook in range of initial address "+addr+" going backwards. Offset from that: "+num_of_addresses_advanced+" addresses, "+num_of_functions_advanced+" functions.");
				num_of_functions_advanced++; //in this case, 1 function means -> hook the present one
				//consume the first of the iterator, since when we are in a function, the first of the backwards iterator will give the function itself
				if (fun_iter.hasNext()) {fun_iter.next();};
			}
			
			while (!we_are_done_for_RangeFunctions && fun_iter.hasNext())
			{
				newfun=fun_iter.next();
				offset_of_new_fun_end=newfun.getBody().getMaxAddress().getOffset();
				offset_of_new_fun_start=newfun.getEntryPoint().getOffset();
				num_of_addresses_advanced=(int) (initial_addr_offset-offset_of_new_fun_start);
				num_of_functions_advanced++;

				if ( num_of_functions_advanced>this.advancedhookoptionsdialog.RangeFunctionsNum)
				{
					we_are_done_for_RangeFunctions=true;
					break;
				}
				generate_snippet_hook_for_address(newfun.getEntryPoint(),false,"Function hook in range of initial address "+addr+" going backwards. Offset from that: "+num_of_addresses_advanced+" addresses, "+num_of_functions_advanced+" functions.");
			
				if (num_of_functions_advanced%100==0 && this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
				if (num_of_functions_advanced%1000==0) {this.incoming_monitor.setMessage("Range for functions (backwards) "+num_of_functions_advanced+"...");}
			}
		}
	
		if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user

		
		/* Function name regex hooking */
		if (this.advancedhookoptionsdialog.isFunctionRegexCheckBoxchecked)
		{
			String regex_for_fun_name=this.advancedhookoptionsdialog.FunctionRegexTextField.getText();
			Pattern pattern= Pattern.compile(regex_for_fun_name,Pattern.CASE_INSENSITIVE);
			FunctionIterator fun_iter=this.current_program_listing.getFunctions(true);
			int num_of_functions_processed=0;
			
			
			if (this.incoming_monitor.isCancelled()) {return;}
			this.incoming_monitor.setMessage("Function hooking by regex...");
			
			while(fun_iter!=null && fun_iter.hasNext())
			{
				Function newfun=fun_iter.next();
				num_of_functions_processed++;
				String name_of_newfun=newfun.getName(true).replace("\"", "_");
				
				if (pattern.matcher(name_of_newfun).matches())
				{
					generate_snippet_hook_for_address(newfun.getEntryPoint(),false,"Function hook to function "+name_of_newfun+" due to matching regex:"+regex_for_fun_name);
				}
				if (num_of_functions_processed%100==0 && this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
			}
			
		
		}
		
		
		/* Function (mangled) name regex hooking */
		if (this.advancedhookoptionsdialog.isFunctionMangledNameRegexCheckBoxchecked)
		{
			String regex_for_fun_mangled_name=this.advancedhookoptionsdialog.FunctionMangledNameRegexTextField.getText();
			Pattern pattern= Pattern.compile(regex_for_fun_mangled_name,Pattern.CASE_INSENSITIVE);
			FunctionIterator fun_iter=this.current_program_listing.getFunctions(true);
			int num_of_functions_processed=0;
			
			if (this.incoming_monitor.isCancelled()) {return;}
			this.incoming_monitor.setMessage("Function hooking by regex...");
			
			while(fun_iter!=null && fun_iter.hasNext())
			{
				Function newfun=fun_iter.next();
				num_of_functions_processed++;
				String name_of_newfun=newfun.getName(true).replace("\"", "_");
				
				SymbolTable incoming_symbol_table=this.incoming_program.getSymbolTable();
				SymbolIterator symbol_interator=incoming_symbol_table.getSymbolsAsIterator(newfun.getEntryPoint());
				while(symbol_interator!=null && symbol_interator.hasNext())
				{
					Symbol next_symbol=symbol_interator.next();
					String symbol_name=next_symbol.getName();
					if (symbol_name.startsWith("_Z") || symbol_name.startsWith("?"))
					{
						//Mangled Symbol. TODO: Provide a better check if a symbol is in a mangled form
						if (pattern.matcher(symbol_name).matches())
						{
							generate_snippet_hook_for_address(newfun.getEntryPoint(),false,"Function hook to function "+name_of_newfun+" due to matching regex of mangled name:"+regex_for_fun_mangled_name);
						}
					}
				}
				
				if (num_of_functions_processed%100==0 && this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
			}
		}
		
		if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user

		/*Hook all imported symbols*/
		if (this.advancedhookoptionsdialog.isHookImportsCheckBoxchecked)
		{
			SymbolTable symboltable=this.current_program.getSymbolTable();
			FunctionIterator fun_iter=this.current_program_listing.getFunctions(true);


			HashMap<String,Function> hashmap_of_functions=new HashMap<String,Function>();
			int num_of_symbols_processed=0;
			SymbolIterator symbol_interator=symboltable.getExternalSymbols();
			
			this.incoming_monitor.setMessage("Hooking imports...");
			
			while(fun_iter!=null && fun_iter.hasNext())
			{
				Function newfun=fun_iter.next();
				if (newfun.getName(true).startsWith("<EXTERNAL>")) //getName(true) returns the namespace as well
				{
					hashmap_of_functions.put(newfun.getName(), newfun); //simple getName() returns the name only
				}
			}
			
			
			String imports_hook_str="";
			String spaces="        ";
			String varstr_for_resolver_and_matches=this.utils.generate_random_string_from_pool(this.characters_allowed_in_variable_name,6);
			imports_hook_str+=spaces+"var resolver_"+varstr_for_resolver_and_matches+" =new ApiResolver('module');\n";
			imports_hook_str+=spaces+"var matches_"+varstr_for_resolver_and_matches+";\n";
			while(symbol_interator!=null && symbol_interator.hasNext())
			{
				num_of_symbols_processed++;
				
				Symbol next_symbol=symbol_interator.next();
				if (hashmap_of_functions.containsKey(next_symbol.getName()))
				{
					//we have found the function. TODO: Can the function be identified in  a better way?
					Function identified_function=hashmap_of_functions.get(next_symbol.getName());
					//See if function name contains illegal characters
					//TODO: Mangled names will contain illegal characters, take that into account
					String sanitized_fun_name=identified_function.getName().replaceAll("[^"+this.characters_allowed_in_variable_name+"]", "_");
					if (!sanitized_fun_name.equals(identified_function.getName()))
					{
						imports_hook_str+=spaces+"//Not creating import hook for function with sanitized name:"+sanitized_fun_name+" due to illegal characters\n";
						continue;
					}
					//TODO: This should not call its own code, it should be integrated with the standard Interceptor.attach() hook code generator.
					imports_hook_str+=this.utils.generate_import_hook_str_for_function(identified_function,varstr_for_resolver_and_matches,spaces);
				}
				
				if (num_of_symbols_processed%100==0 && this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
			}
			this.generated_hook_for_imported_functions=imports_hook_str;
		}
		
		
		if (this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
		
		
		/*Hook all exported symbols*/
		if (this.advancedhookoptionsdialog.isHookExportsCheckBoxchecked)
		{
			SymbolTable symboltable=this.current_program.getSymbolTable();
			AddressIterator addr_iter=symboltable.getExternalEntryPointIterator();
			int num_of_addresses_processed=0;
			
			this.incoming_monitor.setMessage("Hooking exports...");
			
			while (addr_iter!=null && addr_iter.hasNext())
			{
				Address external_entry_point=addr_iter.next();
				num_of_addresses_processed++;
				
				generate_snippet_hook_for_address(external_entry_point,false,"Exported symbol which is an entry point");
				if (num_of_addresses_processed%100==0 && this.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user
			}
		}

	}
	
	
		

	
	protected String gather_all_generated_hooks()
	{
		String hook_str="";
		StringBuffer sb=new StringBuffer(10000000); //Much faster than simple string concatenation when doing it for many strings
		
		if (this.incoming_monitor.isCancelled()) {return "";} //check for cancellation by the user)
		this.incoming_monitor.setMessage("Gathering all generated hooks in one...");
		

		//handling the case where it is requested to make a memory scan for a specific pattern
		if (this.isAdvanced && this.advancedhookoptionsdialog.isMemoryScanPatternCheckBoxchecked)
		{
			InstructionSearchPatternHandler pattern_handler= new InstructionSearchPatternHandler(this.incoming_plugintool,this.current_program,this.advancedhookoptionsdialog.MemoryScanPatternTextField.getText(),this.current_program_name_sanitized,"        ");
			sb.append(pattern_handler.return_frida_code_for_incoming_instruction_pattern());
			sb.append("\n");
		}
		
		if (this.incoming_monitor.isCancelled()) {return "";} //check for cancellation by the user)
		
		//Include the variables and functions that may need declaration and apply for all the hooks
		sb.append(this.utils.return_code_for_initialization_of_functions_and_variables_before_the_hooks());
		
		
		//Now iterate over all generated hooks
		int i;
		for (i=0;i<this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch;i++)
		{
			sb.append(this.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.get(i));
			if (this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.containsKey(i))
			{
				sb.append(this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.get(i));
			}
			
			if (i%100==0 && this.incoming_monitor.isCancelled()) {return "";} //check for cancellation by the user
			if (i%1000==0) {this.incoming_monitor.setMessage("Gathering all generated hooks in one "+(int)((i*100)/this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch)+"%...");}

		}
		/*Careful: There might be Messages_to_be_included_between_hooks after the last legitimate hook, which will have maxed out index*/
		if (this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.containsKey(this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch))
		{
			sb.append(this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.get(this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch));
		}
	
		
		//If we have many try/catch blocks, we should calculate the successes/failures and print them in the end
		if (this.isAdvanced && this.advancedhookoptionsdialog.isIncludeInterceptorTryCatchcheckboxchecked)
		{
			sb.append("\n");
			sb.append("        console.log('Successful Interceptor hooks:'+counter_for_successful_Interceptor_hooks+', failed Interceptor hooks:'+counter_for_failed_Interceptor_hooks);\n");
		}
		
		
		hook_str=sb.toString();
		if (this.consoleService!=null)
		{
			this.consoleService.println("// Gathering generated hooks completed, outputting to the user...");
		}
		this.incoming_monitor.setMessage("Outputting to the user...");
		return hook_str;
	}
	

	protected String generate_interceptor_attach_hook(Address addr,Function current_function,String function_name_with_current_addr,int parameter_count)
	{
		String hook_str="";

		hook_str=hook_str.concat("        "+this.utils.generate_try_catch_text_before_interceptor_hook()+"Interceptor.attach(dynamic_address_of_"+function_name_with_current_addr+", {\n");
		if (this.include_onEnter_in_function_hooks)
		{
			hook_str=hook_str.concat("                    onEnter: function(args) {\n")
							 .concat("                        console.log("+this.utils.tid_and_indent_code()+"\"Entered "+function_name_with_current_addr+"\");\n");
			
			boolean include_names_of_arguments=false;
			if (this.isAdvanced && this.advancedhookoptionsdialog.isIncludeFunParamNamescheckboxchecked)
			{
				if (parameter_count>=1)
				{
					if (this.utils.do_sanitized_function_argument_names_result_in_name_conflicts(current_function))
					{
						include_names_of_arguments=false;
						hook_str+="                        // Conflicting sanitized names of function parameters, as such arguments will not be named\n";
					}
					else
					{
						include_names_of_arguments=true;
						//In this case, the names of the arguments must be put inside the function and variables should be declared
						for (int i=0;i<parameter_count;i++)
						{
							hook_str+="                        this.arg_"+this.utils.return_sanitized_name_of_parameter_for_function_at_position(current_function, i)+"=args["+i+"];\n";
						}
					}
				}
			}
			
				
			/* Put the parameters in the hook code*/
			if (parameter_count>=1 && this.utils.user_options_allow_printing_of_params()) {
						   hook_str+="                        console.log("+this.utils.tid_and_indent_code()+"'";
						   for (int i=0;i<parameter_count;i++)
						   {
							   if (include_names_of_arguments)
							   {
								   hook_str+="args["+i+"](this.arg_"+this.utils.return_sanitized_name_of_parameter_for_function_at_position(current_function, i)+")='+args["+i+"]";
							   }
							   else
							   {
								   hook_str+="args["+i+"]='+args["+i+"]";
							   }
							   if (i<parameter_count-1) { hook_str+="+' , "; }
							   else { hook_str+=");\n"; }
						   }
			}
			if (this.isAdvanced && this.advancedhookoptionsdialog.isOutputReasonForHookGenCheckboxchecked)
			{
				//put the placeholder for the reasons of hooking. This will be replaced when backpatching
				hook_str=hook_str.concat("                        console.log("+this.utils.tid_and_indent_code()+"\"Reasons for hooking: PLACEHOLDER_FOR_REASONS_FOR_HOOKING_"+addr+"\")\n");
			}
			if (this.isAdvanced && this.advancedhookoptionsdialog.isGenerateBacktraceCheckboxchecked)
			{
				hook_str=hook_str.concat(this.utils.generate_backtrace_for_hook(true));
			}
			if (this.isAdvanced && this.advancedhookoptionsdialog.isIncludeCustomTextcheckboxchecked)
			{
				hook_str=hook_str.concat("                        "+this.advancedhookoptionsdialog.IncludeCustomTextTextField.getText()+"\n");
			}
			if (this.isAdvanced && this.utils.can_there_be_any_reason_why_this_address_may_need_code_that_is_later_added_in_the_hook(addr))
			{
				hook_str=hook_str.concat("PLACEHOLDER_FOR_HOOK_CODE_TO_BE_ADDED_LATER_"+addr);
			}
			hook_str=hook_str.concat("                        // this.context.x0=0x1;\n")
							 .concat(this.utils.increase_console_indent_if_chosen())
							 .concat("                    }");
		}
		if (this.include_onEnter_in_function_hooks && this.include_onLeave_in_function_hooks) 
		{
			hook_str=hook_str.concat(",\n");
		}
		if (this.include_onLeave_in_function_hooks)
		{
			hook_str=hook_str.concat("                    onLeave: function(retval) {\n")
							 .concat(this.utils.decrease_console_indent_if_chosen())
						 	 .concat("                        console.log("+this.utils.tid_and_indent_code()+"\"Exited "+function_name_with_current_addr+", retval:\"+retval);\n")
						 	 .concat("                        // retval.replace(0x1);\n")
						 	 .concat("                    }\n");
		}
		else
		{
			hook_str=hook_str.concat("\n");
		}
		hook_str=hook_str.concat("        }); "+this.utils.generate_try_catch_text_after_interceptor_hook(addr)+"\n\n");
		
		return hook_str;
	}
	
	

	protected String generate_interceptor_replace_hook(Address addr,Function current_function,String function_name_with_current_addr,int parameter_count)
	{
		String hook_str="";
		
		/*Generate strings for params*/
		String str_for_types_of_params="";
		String str_for_params_in_nativecallback="";
		
		for (int i=0;i<parameter_count;i++)
		{
			DataType this_param_datatype=current_function.getParameter(i).getDataType();

			str_for_types_of_params+=this.utils.get_frida_nativefun_str_for_parameter(this_param_datatype);
			str_for_params_in_nativecallback+="arg_"+i;
			if (i<parameter_count -1)
			{
				str_for_types_of_params+=",";
				str_for_params_in_nativecallback+=",";
			}
		}
		str_for_types_of_params="["+str_for_types_of_params+"]";
		
		String str_for_return_type="";
		
		/*Generate string for return type*/
		if (current_function.getReturnType().toString()=="void")
		{
			str_for_return_type+="'void'";
		}
		else
		{
			str_for_return_type+=this.utils.get_frida_nativefun_str_for_parameter(current_function.getReturnType());
		}
		String nativefunction_str="dynamic_address_of_"+function_name_with_current_addr+","+str_for_return_type+","+str_for_types_of_params;
		
		hook_str=hook_str.concat("        var NativeFunction_of_"+function_name_with_current_addr+"= new NativeFunction("+nativefunction_str+");\n");
		
		hook_str=hook_str.concat("        "+this.utils.generate_try_catch_text_before_interceptor_hook()+"Interceptor.replace(dynamic_address_of_"+function_name_with_current_addr+",new NativeCallback(("+str_for_params_in_nativecallback+") => {\n");
		
		hook_str=hook_str.concat("                        console.log("+this.utils.tid_and_indent_code()+"\"Entered "+function_name_with_current_addr+"\");\n");
		if (this.isAdvanced && this.advancedhookoptionsdialog.isOutputReasonForHookGenCheckboxchecked)
		{
			//put the placeholder for the reasons of hooking. This will be replaced when backpatching
			hook_str=hook_str.concat("                        console.log("+this.utils.tid_and_indent_code()+"\"Reasons for hooking: PLACEHOLDER_FOR_REASONS_FOR_HOOKING_"+addr+"\")\n");
		}
		
		boolean include_names_of_arguments=false;
		if (this.isAdvanced && this.advancedhookoptionsdialog.isIncludeFunParamNamescheckboxchecked)
		{
			if (parameter_count>=1)
			{
				if (this.utils.do_sanitized_function_argument_names_result_in_name_conflicts(current_function))
				{
					include_names_of_arguments=false;
					hook_str+="                        // Conflicting sanitized names of function parameters, as such arguments will not be named\n";
				}
				else
				{
					include_names_of_arguments=true;
					//In this case, the names of the arguments must be put inside the function and variables should be declared
					for (int i=0;i<parameter_count;i++)
					{
						hook_str+="                        var arg_"+this.utils.return_sanitized_name_of_parameter_for_function_at_position(current_function, i)+"=args["+i+"];\n";
					}
				}
			}
		}

		
			if (parameter_count>=1 && this.utils.user_options_allow_printing_of_params()) {
						   hook_str+="                        console.log("+this.utils.tid_and_indent_code()+"'";
						   for (int i=0;i<parameter_count;i++)
						   {
							   if (include_names_of_arguments)
							   {
								   hook_str+="args["+i+"](arg_"+this.utils.return_sanitized_name_of_parameter_for_function_at_position(current_function, i)+")='+args["+i+"]";
							   }
							   else
							   {
								   hook_str+="args["+i+"]='+arg_"+i+"";
							   }
							   if (i<parameter_count-1) { hook_str+="+' , "; }
							   else { hook_str+=");\n"; }
						   }
			}
		if (this.isAdvanced && this.advancedhookoptionsdialog.isGenerateBacktraceCheckboxchecked)
		{
			hook_str=hook_str.concat(this.utils.generate_backtrace_for_hook(true));
		}
		if (this.isAdvanced && this.advancedhookoptionsdialog.isIncludeCustomTextcheckboxchecked)
		{
			hook_str=hook_str.concat("                        "+this.advancedhookoptionsdialog.IncludeCustomTextTextField.getText()+"\n");
		}
		if (this.isAdvanced && this.utils.can_there_be_any_reason_why_this_address_may_need_code_that_is_later_added_in_the_hook(addr))
		{
			hook_str=hook_str.concat("PLACEHOLDER_FOR_HOOK_CODE_TO_BE_ADDED_LATER_"+addr);
		}
		
		hook_str=hook_str.concat(this.utils.increase_console_indent_if_chosen());
		//call the original function
		hook_str=hook_str.concat("                        var retval=NativeFunction_of_"+function_name_with_current_addr+"("+str_for_params_in_nativecallback+");\n");
		
		hook_str=hook_str.concat(this.utils.decrease_console_indent_if_chosen());

		if (current_function.getReturnType().toString()!="void")
		{
			hook_str=hook_str.concat("                        console.log("+this.utils.tid_and_indent_code()+"\"Exited "+function_name_with_current_addr+", retval:\"+retval);\n");
			hook_str=hook_str.concat("                        return retval;\n");
		}
		else
		{
			hook_str=hook_str.concat("                        console.log("+this.utils.tid_and_indent_code()+"\"Exited "+function_name_with_current_addr+"\");\n");
		}
		hook_str=hook_str.concat("        },"+str_for_return_type+","+str_for_types_of_params+")); "+this.utils.generate_try_catch_text_after_interceptor_hook(addr)+"\n\n");
		
		return hook_str;
	}
	
	
	
	
	/*This function generates the snippet hook, and stores it into the internal data structures*/
	protected void generate_snippet_hook_for_address( Address addr, Boolean print_debug, String reason_for_hook_generation) {
		
		if (this.internal_structures_for_hook_generation.Addresses_for_current_hook_str.containsKey(addr.toString()))
		{
			//Update the hashmap to reflect that another reason was added for the address to be hooked
			String tmpstr=this.internal_structures_for_hook_generation.Addresses_for_current_hook_str.get(addr.toString());
			this.internal_structures_for_hook_generation.Addresses_for_current_hook_str.put(addr.toString(),tmpstr.concat("|").concat(reason_for_hook_generation));
			
			//Set the intermediate message for this index
			if(this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.containsKey(this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch))
			{
				String previous_contents= this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.get(this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch);
				this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.put(this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch, 
																										previous_contents+" //Address:"+addr+", already registered interceptor for that address\n");
			}
			else
			{
				this.internal_structures_for_hook_generation.Messages_to_be_included_between_hooks.put(this.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch, 
						" //Address:"+addr+", already registered interceptor for that address\n");
			}
			return;
		}
		
		//Try to recalculate some parameters
		Function current_function = this.current_program.getFunctionManager().getFunctionContaining(addr);
		Instruction current_instruction=this.current_program_listing.getInstructionAt(addr); //The current address may not be in an undefined function, but it may be in an instruction

		if (current_instruction==null)
		{
			//The data structures should be updated
			String in_place_of_hook=" //Address:"+addr+", not an instruction\n";
			this.utils.update_internal_data_structures(addr,in_place_of_hook,"not an instruction");
			return;
		}
		
		if (this.isAdvanced && this.advancedhookoptionsdialog.isDoNotHookThunkFunctionscheckboxchecked && 
				current_function!=null && current_function.isThunk() && addr.equals(current_function.getEntryPoint()) )
		{
			//Similarly, the data structures should be updated
			String in_place_of_hook=" //Address:"+addr+" is a thunk function, not hooking\n";
			this.utils.update_internal_data_structures(addr,in_place_of_hook,"thunk function, not hooking");
			return;
		}
		
		if (this.isAdvanced && this.advancedhookoptionsdialog.isDoNotHookExternalFunctionscheckboxchecked && 
				current_function!=null && current_function.isExternal() && addr.equals(current_function.getEntryPoint()) )
		{
			//Similarly, the data structures should be updated
			String in_place_of_hook=" //Address:"+addr+" is an external function, not hooking\n";
			this.utils.update_internal_data_structures(addr,in_place_of_hook,"external function, not hooking");
			return;
		}

		
		Address current_function_entry_point;
		Boolean we_are_at_start_of_function;
		String current_function_name_sanitized="";
		
		
		if (current_function!=null)
		{
			current_function_entry_point=current_function.getEntryPoint();
			we_are_at_start_of_function=current_function_entry_point.equals(addr);
			current_function_name_sanitized=current_function.getName(true).replaceAll("[^"+this.characters_allowed_in_variable_name+"]", "_");
		}
		else
		{
			we_are_at_start_of_function=false;
			current_function_entry_point=null;
		}

		
		if (print_debug)
		{
			System.out.println("Address:"+addr);
			System.out.println("Program name:"+this.current_program_name);
			System.out.println("Program base:"+this.image_base);
			System.out.println("Program language:"+this.current_program_language);
			System.out.println("Program processor:"+this.current_program_processor);
			if (current_function!=null)
			{
				System.out.println("Current function:"+current_function);
				System.out.println("Current function entry point:"+current_function_entry_point);
			}
		}

		
		String hook_str="";

		/*for when we are at the start of a function*/
		String function_name_with_current_addr="";
			
		if (we_are_at_start_of_function && !(this.isAdvanced && this.advancedhookoptionsdialog.isGenerateNormalAddressHooksForFunctionBeginningscheckboxchecked))
		{
			//If we are at the start of a function and we are not forced to treat the address as a normal, non function-beginning one
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

			//String.concat() is the fastest, but "+" is also used for code clarity. 
			hook_str=hook_str.concat("        var offset_of_"+function_name_with_current_addr+"=0x"+Long.toHexString(addr.getOffset()-this.image_base.getOffset())+";\n")
							 .concat("        var dynamic_address_of_"+function_name_with_current_addr+"=Module.findBaseAddress(module_name_"+this.current_program_name_sanitized+").add(offset_of_"+function_name_with_current_addr+");\n")
							 .concat(this.utils.populate_data_structures_that_link_addresses_and_function_names("        ","dynamic_address_of_"+function_name_with_current_addr,current_function_name_sanitized,current_function));
			
			String errors_if_interceptor_replace_is_used=this.utils.identify_errors_if_interceptor_replace_is_used(current_function,parameter_count);
			//empty string means that no problems are identified
			if (errors_if_interceptor_replace_is_used=="" && !this.use_interceptor_attach_instead_of_replace_in_function_hooks)
			{
				hook_str=hook_str.concat(generate_interceptor_replace_hook(addr,current_function,function_name_with_current_addr,parameter_count));
			}
			else
			{
				hook_str=hook_str.concat(errors_if_interceptor_replace_is_used);// this is the error message from before if there is any
				hook_str=hook_str.concat(generate_interceptor_attach_hook(addr,current_function,function_name_with_current_addr,parameter_count));
			}
		}
		else
		{
			//this is the case for all non-function beginning addresses
			String str_for_current_function_if_any="";
			String str_in_place_of_current_function_name_sanitized="not in a function";
			if (current_function!=null && !current_function_name_sanitized.equals(""))
			{
				str_for_current_function_if_any=", which is inside function "+current_function_name_sanitized;
				str_in_place_of_current_function_name_sanitized=current_function_name_sanitized;
			}
					
			//String.concat() is the fastest, but "+" is also used for code clarity.
			hook_str=hook_str.concat("        var offset_of_"+addr+"=0x"+Long.toHexString(addr.getOffset()-this.image_base.getOffset())+";\n")
							 .concat("        var dynamic_address_of_"+addr+"=Module.findBaseAddress(module_name_"+this.current_program_name_sanitized+").add(offset_of_"+addr+");\n")
							 .concat(this.utils.populate_data_structures_that_link_addresses_and_function_names("      ","dynamic_address_of_"+addr,str_in_place_of_current_function_name_sanitized,current_function))

							 
							 .concat("        function function_to_call_when_code_reaches_"+addr+"(){\n")
							 .concat("            console.log("+this.utils.tid_and_indent_code()+"'Reached address 0x"+addr+str_for_current_function_if_any+"');\n");
			if (this.isAdvanced && this.advancedhookoptionsdialog.isOutputReasonForHookGenCheckboxchecked)
			{
				//put the placeholder for the reasons of hooking. This will be replaced when backpatching
				hook_str=hook_str.concat("            console.log("+this.utils.tid_and_indent_code()+"\"Reasons for hooking: PLACEHOLDER_FOR_REASONS_FOR_HOOKING_"+addr+"\")\n");
			}
			if (this.isAdvanced && this.advancedhookoptionsdialog.isGenerateBacktraceCheckboxchecked)
			{
				hook_str=hook_str.concat(this.utils.generate_backtrace_for_hook(false));
			}
			if (this.isAdvanced && this.advancedhookoptionsdialog.isIncludeCustomTextcheckboxchecked)
			{
				hook_str=hook_str.concat("            "+this.advancedhookoptionsdialog.IncludeCustomTextTextField.getText()+"\n");
			}
			if (this.isAdvanced && this.utils.can_there_be_any_reason_why_this_address_may_need_code_that_is_later_added_in_the_hook(addr))
			{
				hook_str=hook_str.concat("PLACEHOLDER_FOR_HOOK_CODE_TO_BE_ADDED_LATER_"+addr);
			}
			hook_str=hook_str.concat("            //this.context.x0=0x1;\n")
							 .concat("        }\n")

							 .concat("        "+this.utils.generate_try_catch_text_before_interceptor_hook()+"Interceptor.attach(dynamic_address_of_"+addr+", function_to_call_when_code_reaches_"+addr+"); "+this.utils.generate_try_catch_text_after_interceptor_hook(addr)+"\n\n");

		}
		
		this.utils.update_internal_data_structures(addr,hook_str,reason_for_hook_generation);
		
	}
	
	

}


/*Basically a 4-tuple of data, to be inserted to data structures for keeping track of function references*/
class ContainerForFunctionReferences
{
	public Function fun;
	public int index_of_source_at_previous_depth;
	public int first_index_of_dest_at_next_depth;
	public int current_depth;
	
	public ContainerForFunctionReferences(Function fun,int index_of_source_at_previous_depth, int first_index_of_dest_at_next_depth, int current_depth)
	{
		this.fun=fun;
		this.index_of_source_at_previous_depth=index_of_source_at_previous_depth;
		this.first_index_of_dest_at_next_depth=first_index_of_dest_at_next_depth;
		this.current_depth=current_depth; 
	}

}