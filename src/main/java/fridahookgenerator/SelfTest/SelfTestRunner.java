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

package fridahookgenerator.SelfTest;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import fridahookgenerator.AdvancedHookOptionsDialog;
import fridahookgenerator.FridaHookGeneratorAPIHandler;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Reference;

/*
 * Drives the whole self test: runs the checks that need nothing, then asks the plugin to generate a script for a series
 * of combinations of options, and hands every one of them to the checker.
 *
 * The addresses that are used are not written into this file: they are looked for inside the program that is loaded, so
 * that the self test works on whatever binary the user happens to have open. What it looks for is the shapes that have
 * caused problems before: a plain function, a thunk (a thunk is usually a computed jump, which is what the computed call
 * code has to deal with), an instruction that is a computed call, and an address that is not the beginning of a function.
 *
 * Adding a combination is one call to run_one_combination(), which is the point: the matrix is meant to grow.
 */
public class SelfTestRunner {

	/*
	 * How much of the self test to run. The whole of it generates a script for every combination and then examines every
	 * hook of every one of those scripts, which on a large program is a lot of work, so there are three sizes:
	 *
	 *   LOW    : the combinations that every other one is built on, a handful of hooks examined per script, and nothing
	 *            that walks over the whole program. Meant to be run often, while something is being changed.
	 *   MEDIUM : most of the combinations, and enough hooks examined to be representative. Meant to be run before a commit.
	 *   FULL   : every combination, including the ones that walk over every function and every symbol of the program, and
	 *            every hook of every script examined. Meant to be run when there is time.
	 */
	public enum Level {
		LOW,
		MEDIUM,
		FULL
	};

	protected PluginTool incoming_plugintool;
	protected Program current_program;
	protected SelfTestReport report;
	protected GeneratedScriptChecker checker;
	protected Level level;
	protected int how_many_combinations_were_skipped_because_of_the_level;

	/*
	 * One address of the program that is worth running the combinations against, together with what kind of thing it is.
	 * The kind is what decides which combinations make sense for it: the options that change the shape of a function hook
	 * have nothing to do on an address in the middle of a function, and the options about the computed calls have nothing to
	 * do on an address that is not one.
	 */
	public class RepresentativeAddress
	{
		public Address address;
		public String description;
		public Boolean it_is_the_beginning_of_a_function=false;
		public Boolean it_is_a_computed_call=false;
		public Boolean it_is_a_thunk=false;
		public Boolean it_is_external=false;
		public Boolean it_is_not_inside_a_function=false;
		public Boolean it_is_not_an_instruction=false;

		public RepresentativeAddress(Address address,String description)
		{
			this.address=address;
			this.description=description;
		}
	}

	protected ArrayList<RepresentativeAddress> representative_addresses=new ArrayList<RepresentativeAddress>();

	/*The addresses that were found inside the loaded program and that the combinations are run against*/
	protected Address address_of_a_function;
	protected Address address_of_a_thunk_function;
	protected Address address_of_a_computed_call;
	protected Address address_that_is_not_a_function_beginning;
	protected String name_of_a_function_for_the_regular_expression;

	public SelfTestRunner(PluginTool incoming_plugintool,Program current_program)
	{
		this(incoming_plugintool,current_program,Level.MEDIUM);
	}

	public SelfTestRunner(PluginTool incoming_plugintool,Program current_program,Level level)
	{
		this.incoming_plugintool=incoming_plugintool;
		this.current_program=current_program;
		this.level=level;
		this.how_many_combinations_were_skipped_because_of_the_level=0;
		this.report=new SelfTestReport();
		this.checker=new GeneratedScriptChecker(current_program,this.report,return_how_many_hooks_to_examine_per_script(),return_how_many_things_to_enumerate_from_the_database());
	}

	/*Whether the level that was asked for is at least the one that a step needs*/
	protected Boolean the_level_is_at_least(Level level_that_is_needed)
	{
		return Boolean.valueOf(this.level.ordinal()>=level_that_is_needed.ordinal());
	}

	/*How many hooks of every generated script are examined one by one*/
	protected int return_how_many_hooks_to_examine_per_script()
	{
		if (this.level==Level.LOW)
		{
			return 3;
		}
		if (this.level==Level.MEDIUM)
		{
			return 25;
		}
		return 100000;	//every hook, with a bound that no real script reaches
	}

	/*How many of the representative addresses of the program the combinations are run against*/
	protected int return_how_many_addresses_to_run_against()
	{
		if (this.level==Level.LOW)
		{
			return 1;
		}
		if (this.level==Level.MEDIUM)
		{
			return 3;
		}
		return 100;	//every one that was found
	}

	/*How many things the database is asked to enumerate for a check: the references, the functions of a range, the matches of a regular expression*/
	protected int return_how_many_things_to_enumerate_from_the_database()
	{
		if (this.level==Level.LOW)
		{
			return 5;
		}
		if (this.level==Level.MEDIUM)
		{
			return 25;
		}
		return 200;
	}

	public SelfTestReport return_the_report()
	{
		return this.report;
	}

	/*The whole self test. Returns the report, which the caller prints wherever it wants*/
	public SelfTestReport run_everything()
	{
		this.report.add_info("the level of the self test","level",
				"The level that was asked for is "+this.level+" , which examines up to "+return_how_many_hooks_to_examine_per_script()
				+" hooks of every generated script and enumerates up to "+return_how_many_things_to_enumerate_from_the_database()+" things from the database per check","");
		this.report.add_info("the program that was used","program",
				"Ran against "+this.current_program.getName()+" , language "+this.current_program.getLanguage().getLanguageID()+" , image base "+this.current_program.getImageBase(),"");

		new Level0Checks(this.current_program,this.report).run_all_the_level0_checks();

		find_the_addresses_to_run_against();
		run_all_the_combinations();

		if (this.how_many_combinations_were_skipped_because_of_the_level>0)
		{
			this.report.add_skipped_step(this.how_many_combinations_were_skipped_because_of_the_level+" combinations of options",
					"they need a level higher than "+this.level+" , run the full self test to include them");
		}

		return this.report;
	}

	/*----------------------------------------------------------------------------------------------------------------*/

	/*
	 * Looks inside the program for the shapes that the combinations need. Everything that is not found is simply left null,
	 * and the combinations that need it are reported as skipped.
	 */
	protected void find_the_addresses_to_run_against()
	{
		int how_many_functions_examined=0;
		FunctionIterator function_iterator=this.current_program.getListing().getFunctions(true);
		while (function_iterator!=null && function_iterator.hasNext() && how_many_functions_examined<20000)
		{
			Function function=function_iterator.next();
			how_many_functions_examined++;
			/*Only a function whose beginning really is an instruction is of any use, as the plugin hooks nothing else*/
			if (this.current_program.getListing().getInstructionAt(function.getEntryPoint())==null)
			{
				continue;
			}
			if (function.isThunk())
			{
				if (this.address_of_a_thunk_function==null)
				{
					this.address_of_a_thunk_function=function.getEntryPoint();
				}
				continue;
			}
			if (this.address_of_a_function==null)
			{
				this.address_of_a_function=function.getEntryPoint();
				this.name_of_a_function_for_the_regular_expression=function.getName(true);
			}
		}

		int how_many_instructions_examined=0;
		InstructionIterator instruction_iterator=this.current_program.getListing().getInstructions(true);
		while (instruction_iterator!=null && instruction_iterator.hasNext() && how_many_instructions_examined<200000)
		{
			Instruction instruction=instruction_iterator.next();
			how_many_instructions_examined++;
			if (this.address_of_a_computed_call==null
					&& can_the_destination_of_this_instruction_be_reported(instruction,this.current_program.getLanguage().getLanguageID().toString()).booleanValue())
			{
				this.address_of_a_computed_call=instruction.getAddress();
			}
			if (this.address_that_is_not_a_function_beginning==null)
			{
				Function function_containing=this.current_program.getListing().getFunctionContaining(instruction.getAddress());
				if (function_containing!=null && !function_containing.getEntryPoint().equals(instruction.getAddress()))
				{
					this.address_that_is_not_a_function_beginning=instruction.getAddress();
				}
			}
			if (this.address_of_a_computed_call!=null && this.address_that_is_not_a_function_beginning!=null)
			{
				break;
			}
		}

		String what_was_found="a function: "+this.address_of_a_function
				+" , a thunk: "+this.address_of_a_thunk_function
				+" , a computed call: "+this.address_of_a_computed_call
				+" , an address inside a function: "+this.address_that_is_not_a_function_beginning;
		this.report.add_info("the addresses that were used","the four that the whole program combinations use","Looked inside the program for the addresses to run against",what_was_found);

		collect_the_representative_addresses();
	}

	/*----------------------------------------------------------------------------------------------------------------*/
	/*
	 * Collects the addresses of the program that are worth running the combinations against, and remembers what kind of
	 * thing each one is. A combination is then only run against an address whose kind it makes sense for, which is what
	 * stops the self test from asking, for instance, whether a hook that only exists for the beginning of a function was
	 * written for an address in the middle of one.
	 */
	protected void collect_the_representative_addresses()
	{
		Listing listing=this.current_program.getListing();

		/*The plainest one: the first function whose beginning is an instruction*/
		if (this.address_of_a_function!=null)
		{
			RepresentativeAddress one=new RepresentativeAddress(this.address_of_a_function,"the first function of the program");
			one.it_is_the_beginning_of_a_function=true;
			this.representative_addresses.add(one);
		}

		/*The entry point of the program, when it is not the same one*/
		Address entry_point=null;
		AddressIterator address_iterator=this.current_program.getSymbolTable().getExternalEntryPointIterator();
		if (address_iterator!=null && address_iterator.hasNext())
		{
			entry_point=address_iterator.next();
		}
		if (entry_point!=null && listing.getInstructionAt(entry_point)!=null && !entry_point.equals(this.address_of_a_function))
		{
			RepresentativeAddress one=new RepresentativeAddress(entry_point,"an entry point of the program");
			one.it_is_the_beginning_of_a_function=(this.current_program.getFunctionManager().getFunctionAt(entry_point)!=null);
			this.representative_addresses.add(one);
		}

		/*
		 * Now a walk over the functions, looking for the shapes that are worth exercising: the one with the most parameters,
		 * the largest one, one whose name needed sanitizing, and a handful spread evenly over the program so that the self
		 * test is not always looking at the same corner of it.
		 */
		Function function_with_the_most_parameters=null;
		Function largest_function=null;
		Function function_with_an_unusual_name=null;
		ArrayList<Function> functions_spread_over_the_program=new ArrayList<Function>();
		Function thunk_function=null;
		Function external_function=null;

		int how_many_functions_seen=0;
		Function function_that_returns_void=null;
		Function function_with_no_parameters=null;
		int how_many_functions_to_look_at=50000;
		FunctionIterator function_iterator=listing.getFunctions(true);
		while (function_iterator!=null && function_iterator.hasNext() && how_many_functions_seen<how_many_functions_to_look_at)
		{
			Function function=function_iterator.next();
			how_many_functions_seen++;
			if (listing.getInstructionAt(function.getEntryPoint())==null)
			{
				continue;	//the plugin hooks nothing that is not an instruction
			}
			if (function.isThunk())
			{
				if (thunk_function==null) { thunk_function=function; }
				continue;
			}
			if (function.isExternal())
			{
				if (external_function==null) { external_function=function; }
				continue;
			}
			if (function_with_the_most_parameters==null || function.getParameterCount()>function_with_the_most_parameters.getParameterCount())
			{
				function_with_the_most_parameters=function;
			}
			if (function.getBody()!=null && (largest_function==null || function.getBody().getNumAddresses()>largest_function.getBody().getNumAddresses()))
			{
				largest_function=function;
			}
			String name_of_the_function=function.getName(true);
			if (function_with_an_unusual_name==null && !name_of_the_function.equals(name_of_the_function.replaceAll("[^0-9a-zA-Z_]","_")))
			{
				function_with_an_unusual_name=function;	//a namespace, a colon, a quote: something that has to be sanitized
			}
			/*
			 * A function that returns nothing and a function that takes nothing. Both matter for the Interceptor.replace form:
			 * the first must not end with a "return retval;" and the second has a NativeCallback with an empty list of
			 * parameters, which is where an off by one in the writing of that list would show.
			 *
			 * Careful: the first function of the program is already in the list under another description, and a function that is
			 * already in the list is dropped silently. Both searches used to match it and both used to add nothing at all, which
			 * is why the count of the representative addresses did not move. Skipping the first few functions is enough to get a
			 * function that is really its own case.
			 */
			if (function_that_returns_void==null && how_many_functions_seen>3
					&& function.getReturnType()!=null && function.getReturnType().toString().equals("void"))
			{
				function_that_returns_void=function;
			}
			if (function_with_no_parameters==null && how_many_functions_seen>3 && function.getParameterCount()==0
					&& function.getReturnType()!=null && !function.getReturnType().toString().equals("void"))
			{
				function_with_no_parameters=function;
			}
			if (how_many_functions_seen%997==0 && functions_spread_over_the_program.size()<6)
			{
				functions_spread_over_the_program.add(function);
			}
		}

		add_a_representative_function(function_with_the_most_parameters,"the function with the most parameters ("+(function_with_the_most_parameters==null?0:function_with_the_most_parameters.getParameterCount())+" of them)");
		add_a_representative_function(largest_function,"the largest function of the program");
		add_a_representative_function(function_with_an_unusual_name,"a function whose name has to be sanitized");
		add_a_representative_function(function_that_returns_void,"a function that returns void");
		add_a_representative_function(function_with_no_parameters,"a function with no parameters");
		for (int i=0;i<functions_spread_over_the_program.size();i++)
		{
			add_a_representative_function(functions_spread_over_the_program.get(i),"a function taken from further inside the program");
		}
		if (thunk_function!=null)
		{
			RepresentativeAddress one=new RepresentativeAddress(thunk_function.getEntryPoint(),"a thunk function");
			one.it_is_the_beginning_of_a_function=true;
			one.it_is_a_thunk=true;
			this.representative_addresses.add(one);
		}
		if (external_function!=null)
		{
			RepresentativeAddress one=new RepresentativeAddress(external_function.getEntryPoint(),"an external function");
			one.it_is_the_beginning_of_a_function=true;
			one.it_is_external=true;
			this.representative_addresses.add(one);
		}

		/*
		 * And the computed calls. The two cases are worth keeping apart: one that sits at the beginning of a function, which
		 * is what a veneer of the PLT looks like, and one in the middle of a function. The options that change the shape of a
		 * function hook only ever apply to the first of the two.
		 */
		Address computed_call_at_the_beginning_of_a_function=null;
		Address computed_call_inside_a_function=null;
		int how_many_instructions_seen=0;
		InstructionIterator instruction_iterator=listing.getInstructions(true);
		while (instruction_iterator!=null && instruction_iterator.hasNext() && how_many_instructions_seen<400000)
		{
			Instruction instruction=instruction_iterator.next();
			how_many_instructions_seen++;
			if (!can_the_destination_of_this_instruction_be_reported(instruction,this.current_program.getLanguage().getLanguageID().toString()).booleanValue())
			{
				continue;
			}
			Function function_at_the_instruction=this.current_program.getFunctionManager().getFunctionAt(instruction.getAddress());
			if (function_at_the_instruction!=null)
			{
				if (computed_call_at_the_beginning_of_a_function==null)
				{
					computed_call_at_the_beginning_of_a_function=instruction.getAddress();
				}
			}
			else if (computed_call_inside_a_function==null)
			{
				computed_call_inside_a_function=instruction.getAddress();
			}
			if (computed_call_at_the_beginning_of_a_function!=null && computed_call_inside_a_function!=null)
			{
				break;
			}
		}
		if (computed_call_at_the_beginning_of_a_function!=null)
		{
			RepresentativeAddress one=new RepresentativeAddress(computed_call_at_the_beginning_of_a_function,"a computed call at the beginning of a function");
			one.it_is_the_beginning_of_a_function=true;
			one.it_is_a_computed_call=true;
			this.representative_addresses.add(one);
		}
		if (computed_call_inside_a_function!=null)
		{
			RepresentativeAddress one=new RepresentativeAddress(computed_call_inside_a_function,"a computed call in the middle of a function");
			one.it_is_a_computed_call=true;
			this.representative_addresses.add(one);
		}

		/*An address that is not the beginning of a function goes through a different piece of the generator*/
		if (this.address_that_is_not_a_function_beginning!=null)
		{
			this.representative_addresses.add(new RepresentativeAddress(this.address_that_is_not_a_function_beginning,"an address in the middle of a function"));
		}

		/*
		 * An instruction that no function owns, which is what Ghidra leaves behind wherever it found code but made no function
		 * out of it. The plugin has a branch of its own for it: there is no name to put in the message and no beginning of a
		 * function to write into the dictionaries, so it writes the words "not in a function" instead of a name. Nothing had ever
		 * generated a hook for such an address.
		 */
		Address address_that_no_function_owns=find_an_instruction_that_no_function_owns();
		if (address_that_no_function_owns!=null)
		{
			RepresentativeAddress one=new RepresentativeAddress(address_that_no_function_owns,"an instruction that no function owns");
			one.it_is_not_inside_a_function=true;
			this.representative_addresses.add(one);
		}

		/*
		 * And a place that holds no instruction at all. Every combination has to refuse it, and the interesting part is that it
		 * has to refuse it without writing a broken script: an empty output, or an output that says why it is empty, but never a
		 * hook for an address that cannot be hooked.
		 */
		Address address_that_holds_no_instruction=find_an_address_that_holds_no_instruction();
		if (address_that_holds_no_instruction!=null)
		{
			RepresentativeAddress one=new RepresentativeAddress(address_that_holds_no_instruction,"an address that holds no instruction");
			one.it_is_not_an_instruction=true;
			this.representative_addresses.add(one);
		}

		StringBuffer what_was_found=new StringBuffer(1024);
		for (int i=0;i<this.representative_addresses.size();i++)
		{
			RepresentativeAddress one=this.representative_addresses.get(i);
			what_was_found.append((i>0?" | ":"")+one.address+" ("+one.description+")");
		}
		this.report.add_info("the addresses that were used","how many and which",
				"Found "+this.representative_addresses.size()+" representative addresses of the program, and this level runs the combinations against "
				+Math.min(this.representative_addresses.size(),return_how_many_addresses_to_run_against())+" of them",
				what_was_found.toString());
	}

	/*
	 * Whether the destination of this instruction is one that the plugin undertakes to report.
	 *
	 * Careful: a computed flow is not the same thing as a computed call or jump whose destination can be worked out. Ghidra
	 * reports a computed flow for UD2, the undefined instruction of x86, which has no destination at all: it traps. An address
	 * like that is not a fixture for the options about the computed calls, and choosing it as one makes every combination that
	 * uses it ask for something that cannot exist.
	 *
	 * So the mnemonic is asked for as well, and the lists below are written here on purpose instead of being read out of the
	 * plugin: a fixture that asks the code under test what it feels like doing tests nothing. They have to say the same thing as
	 * does_the_current_instruction_definitely_need_hook_code_to_also_be_added_later() in HookGeneratorUtils, and if the two ever
	 * disagree the combinations about the computed calls start failing, which is the point.
	 */
	public static Boolean can_the_destination_of_this_instruction_be_reported(Instruction instruction,String identifier_of_the_language)
	{
		if (instruction==null || instruction.getFlowType()==null || !instruction.getFlowType().isComputed())
		{
			return false;
		}
		String mnemonic=instruction.getMnemonicString().toLowerCase().trim();
		if (identifier_of_the_language.indexOf("x86:LE:")>=0)
		{
			return Boolean.valueOf(mnemonic.equals("call") || mnemonic.equals("jmp"));
		}
		if (identifier_of_the_language.indexOf("AARCH64:LE:64")>=0)
		{
			return Boolean.valueOf(mnemonic.equals("blr") || mnemonic.equals("br")
					|| mnemonic.equals("blraa") || mnemonic.equals("blrab") || mnemonic.equals("blraaz") || mnemonic.equals("blrabz")
					|| mnemonic.equals("braa") || mnemonic.equals("brab") || mnemonic.equals("braaz") || mnemonic.equals("brabz"));
		}
		if (identifier_of_the_language.indexOf("ARM:LE:32")>=0)
		{
			return Boolean.valueOf(mnemonic.startsWith("bx") || mnemonic.startsWith("blx")
					|| mnemonic.startsWith("mov") || mnemonic.startsWith("ldr"));
		}
		return false;	//an architecture with no parser of the computed calls
	}

	/*
	 * The first instruction of the program that no function contains. Walks the instructions and not the functions, because what
	 * is looked for is exactly what the function manager does not know about.
	 */
	protected Address find_an_instruction_that_no_function_owns()
	{
		Listing listing=this.current_program.getListing();
		InstructionIterator instruction_iterator=listing.getInstructions(true);
		int how_many_were_seen=0;
		while (instruction_iterator!=null && instruction_iterator.hasNext() && how_many_were_seen<200000)
		{
			Instruction instruction=instruction_iterator.next();
			how_many_were_seen++;
			if (this.current_program.getFunctionManager().getFunctionContaining(instruction.getAddress())==null)
			{
				return instruction.getAddress();
			}
		}
		return null;
	}

	/*
	 * A place inside the memory of the program that holds no instruction. The first defined piece of data is the surest one:
	 * it is inside the program, so the address is valid, and it is not code, so every combination has to refuse it.
	 */
	protected Address find_an_address_that_holds_no_instruction()
	{
		Listing listing=this.current_program.getListing();
		DataIterator data_iterator=listing.getDefinedData(true);
		int how_many_were_seen=0;
		while (data_iterator!=null && data_iterator.hasNext() && how_many_were_seen<200000)
		{
			Data data=data_iterator.next();
			how_many_were_seen++;
			if (listing.getInstructionAt(data.getAddress())==null
					&& this.current_program.getFunctionManager().getFunctionContaining(data.getAddress())==null)
			{
				return data.getAddress();
			}
		}
		return null;
	}

	protected void add_a_representative_function(Function function,String description)
	{
		if (function==null)
		{
			return;
		}
		for (int i=0;i<this.representative_addresses.size();i++)
		{
			if (this.representative_addresses.get(i).address.equals(function.getEntryPoint()))
			{
				return;	//already in the list under another description
			}
		}
		RepresentativeAddress one=new RepresentativeAddress(function.getEntryPoint(),description);
		one.it_is_the_beginning_of_a_function=true;
		this.representative_addresses.add(one);
	}

	/*----------------------------------------------------------------------------------------------------------------*/

	/*
	 * Runs the combinations that depend on an address once for every representative address that the level allows, and the
	 * ones that walk over the whole program once.
	 */
	protected void run_all_the_combinations()
	{
		if (this.representative_addresses.size()==0)
		{
			this.report.add_skipped_step("every combination","no address of the program is an instruction that can be hooked");
			return;
		}

		int how_many_addresses_to_run_against=Math.min(this.representative_addresses.size(),return_how_many_addresses_to_run_against());
		for (int i=0;i<how_many_addresses_to_run_against;i++)
		{
			run_the_core_combinations_for(this.representative_addresses.get(i));
		}
		if (this.representative_addresses.size()>how_many_addresses_to_run_against)
		{
			this.report.add_skipped_step((this.representative_addresses.size()-how_many_addresses_to_run_against)+" representative addresses",
					"the level is "+this.level+" , run the full self test to use all of them");
		}

		run_the_combinations_that_walk_the_whole_program();
	}

	/*
	 * The combinations that are run for one address. Every one of them says which kind of address it makes sense for, so a
	 * combination is never asked to prove something about an address that it cannot apply to.
	 */
	protected void run_the_core_combinations_for(RepresentativeAddress representative_address)
	{
		Address address=representative_address.address;
		String on=" [on "+representative_address.description+"]";
		AdvancedHookOptionsDialog options;

		/*The plainest thing the plugin can do: one snippet for one address*/
		options=create_the_options();
		if (options==null) { return; }
		run_one_combination("a snippet for one address"+on,options,address,new_expectations_for(false,address));

		/*The same, as a whole script, for each of the four ways of registering the interceptors*/
		String[] names_of_the_methods={"the default method","the dlopen method","the LoadLibrary method","the module observer method"};
		for (int index_of_the_method=0;index_of_the_method<4;index_of_the_method++)
		{
			options=create_the_options();
			if (options==null) { return; }
			options.isGenerateScriptCheckboxchecked=true;
			options.TypeofScriptGenerationcomboBox.setSelectedIndex(index_of_the_method);
			/*The default method is the one that the quick level runs, the three that wait for a library to be loaded are left to the medium one*/
			Level level_that_is_needed=(index_of_the_method==0)?Level.LOW:Level.MEDIUM;
			run_one_combination(level_that_is_needed,"a script with "+names_of_the_methods[index_of_the_method]+on,options,address,new_expectations_for(true,address));
		}

		/*Everything that adds code inside the hooks*/
		options=create_the_options();
		if (options==null) { return; }
		options.isIncludeInterceptorTryCatchcheckboxchecked=true;
		options.isIncludeTIDAndIndentationcheckboxchecked=true;
		options.isGenerateBacktraceCheckboxchecked=true;
		options.GenerateBacktracecomboBox.setSelectedIndex(2);
		options.isCreateDataStructuresToLinkAddressesAndFunctionNamescheckboxchecked=true;
		options.isCreateDataStructureWithInterceptorAttachObjectscheckboxchecked=true;
		run_one_combination("the try/catch, the thread identifiers, the backtrace and the dictionaries"+on,options,address,new_expectations_for(false,address));

		/*
		 * The four ways of asking for a backtrace, one combination each.
		 * The first two only put a backtrace where a function begins, the last two put one in every hook, and the difference
		 * between the two pairs is exactly what a hook in the middle of a function has to show. The way of index 2 is the one
		 * that the combination above already uses, so it is not repeated here.
		 */
		String[] names_of_the_ways_of_the_backtrace={"the accurate backtracer at the beginnings of the functions",
				"the fuzzy backtracer at the beginnings of the functions","","the fuzzy backtracer in every hook"};
		for (int index_of_the_way=0;index_of_the_way<4;index_of_the_way++)
		{
			if (index_of_the_way==2) { continue; }
			options=create_the_options();
			if (options==null) { return; }
			options.isGenerateBacktraceCheckboxchecked=true;
			options.GenerateBacktracecomboBox.setSelectedIndex(index_of_the_way);
			run_one_combination(Level.MEDIUM,names_of_the_ways_of_the_backtrace[index_of_the_way]+on,options,address,new_expectations_for(false,address));
		}

		/*
		 * A backtrace inside a hook that carries the thread identifiers, so that the line of the backtrace is written by the
		 * same emitter that writes the indentation of the rest of the block. A backtrace that is aligned differently from the
		 * lines around it means that the code that writes it was told the wrong thing about the block it is writing into.
		 */
		options=create_the_options();
		if (options==null) { return; }
		options.isGenerateBacktraceCheckboxchecked=true;
		options.GenerateBacktracecomboBox.setSelectedIndex(3);
		options.isIncludeTIDAndIndentationcheckboxchecked=true;
		options.isOutputReasonForHookGenCheckboxchecked=true;
		run_one_combination(Level.FULL,"the fuzzy backtracer, the thread identifiers and the reasons"+on,options,address,new_expectations_for(false,address));

		/*
		 * Everything that writes something inside a hook, all of it switched on at the same time.
		 * The options are not independent of one another: they write into the same block, one after the other, and the order
		 * and the indentation of what each of them writes is decided in a different place of the generator. A suite that turns
		 * one option on at a time can never see that.
		 */
		options=create_the_options();
		if (options==null) { return; }
		options.isIncludeInterceptorTryCatchcheckboxchecked=true;
		options.isIncludeTIDAndIndentationcheckboxchecked=true;
		options.isGenerateBacktraceCheckboxchecked=true;
		options.GenerateBacktracecomboBox.setSelectedIndex(2);
		options.isCreateDataStructuresToLinkAddressesAndFunctionNamescheckboxchecked=true;
		options.isCreateDataStructureWithInterceptorAttachObjectscheckboxchecked=true;
		options.isOutputReasonForHookGenCheckboxchecked=true;
		options.isIncludeCustomTextcheckboxchecked=true;
		options.IncludeCustomTextTextField.setText("console.log('the custom text that goes first');");
		options.isIncludeCustomTextAftercheckboxchecked=true;
		options.IncludeCustomTextAfterTextField.setText("console.log('the custom text that goes last');");
		options.isIncludeFunParamNamescheckboxchecked=true;
		options.isGenerateScriptCheckboxchecked=true;
		GeneratedScriptChecker.Expectations expectations_for_everything=new_expectations_for(true,address);
		expectations_for_everything.text_that_must_appear_somewhere="the custom text that goes first";
		run_one_combination(Level.MEDIUM,"every option that writes inside a hook, all at once"+on,options,address,expectations_for_everything);

		/*
		 * The same set of options, but as a snippet instead of as a whole script.
		 * A snippet is meant to be pasted into a script that already has the prologue, so it uses the helpers of that prologue
		 * without declaring them: tid_and_indent(), the dictionaries, the counters. That is correct, and the checks have to be
		 * able to tell a name that the host script provides from a name that is simply missing.
		 */
		options=create_the_options();
		if (options==null) { return; }
		options.isIncludeInterceptorTryCatchcheckboxchecked=true;
		options.isIncludeTIDAndIndentationcheckboxchecked=true;
		options.isCreateDataStructuresToLinkAddressesAndFunctionNamescheckboxchecked=true;
		options.isCreateDataStructureWithInterceptorAttachObjectscheckboxchecked=true;
		options.isGenerateBacktraceCheckboxchecked=true;
		options.GenerateBacktracecomboBox.setSelectedIndex(3);
		run_one_combination(Level.MEDIUM,"a snippet that uses the helpers of a prologue it does not carry"+on,options,address,new_expectations_for(false,address));

		/*
		 * Two options that contradict one another: the names of the parameters are asked for and the printing of the parameters
		 * is switched off. The second one has to win and nothing may be printed.
		 */
		options=create_the_options();
		if (options==null) { return; }
		options.isIncludeFunParamNamescheckboxchecked=true;
		options.isDoNotIncludeFunParamscheckboxchecked=true;
		run_one_combination(Level.MEDIUM,"the names of the parameters together with not printing them"+on,options,address,new_expectations_for(false,address));

		/*
		 * Several ways of collecting addresses at the same time. More than one of them can arrive at the same address, and the
		 * plugin has to write one hook that carries every reason instead of two hooks that both hook it.
		 */
		options=create_the_options();
		if (options==null) { return; }
		options.isReferencestoAddressCheckBoxchecked=true;
		options.isOutReferencesfromAddressCheckBoxchecked=true;
		options.isOutReferencesfromFunctionCheckBoxchecked=true;
		options.isRangeFunctionsCheckBoxchecked=true;
		options.RangeFunctionsNum=3;
		options.RangeFunctionsRadioButtonFun.setSelected(true);
		options.isOutputReasonForHookGenCheckboxchecked=true;
		options.isGenerateScriptCheckboxchecked=true;
		run_one_combination(Level.FULL,"four ways of collecting addresses at once, with the reasons"+on,options,address,new_expectations_for(true,null));

		/*
		 * A range of instructions together with the ranges of functions, the try/catch and the dictionaries, as a script that
		 * waits for a library. Many hooks, so the prologue and the epilogue have to be written once and only once around all
		 * of them, and the counters of the try/catch have to be declared before the first hook uses them.
		 */
		options=create_the_options();
		if (options==null) { return; }
		options.isRangeAddressesCheckBoxchecked=true;
		options.RangeAddressesNum=10;
		options.RangeAddressesRadioButtonInstr.setSelected(true);
		options.isRangeFunctionsCheckBoxchecked=true;
		options.RangeFunctionsNum=3;
		options.RangeFunctionsRadioButtonFun.setSelected(true);
		options.isIncludeInterceptorTryCatchcheckboxchecked=true;
		options.isCreateDataStructuresToLinkAddressesAndFunctionNamescheckboxchecked=true;
		options.isCreateDataStructureWithInterceptorAttachObjectscheckboxchecked=true;
		options.isGenerateScriptCheckboxchecked=true;
		options.TypeofScriptGenerationcomboBox.setSelectedIndex(3);	//the module observer method
		run_one_combination(Level.FULL,"two ranges at once inside a script that watches for the modules"+on,options,address,new_expectations_for(true,null));

		/*
		 * The option that hooks the selected address, switched off while the options that follow the references are on.
		 * Every other combination has that option on, so this is the only one that checks that the plugin leaves an address alone
		 * when it is told to. What has to come out is the hooks of the references and no hook for the address itself.
		 *
		 * The option is switched off the way every other option of this suite is switched off, by setting the field. That used to
		 * be overruled: the dialog put its components back to the state they have when a user is about to see them, which ticks
		 * this one, and the virtual pressing of the OK button then read the components back into the options. The dialog that the
		 * api builds now knows that nobody is going to see it and leaves the caller's answer alone.
		 */
		options=create_the_options();
		if (options==null) { return; }
		options.isHookThisAddressCheckBoxchecked=false;
		options.isReferencestoAddressCheckBoxchecked=true;
		options.isFunctionsReferencingAddressCheckBoxchecked=true;
		options.isOutputReasonForHookGenCheckboxchecked=true;
		GeneratedScriptChecker.Expectations expectations_with_the_address_left_alone=new_expectations_for(false,null);
		if (!can_another_option_arrive_at_this_address_as_well(address).booleanValue())
		{
			expectations_with_the_address_left_alone.addresses_that_must_not_be_hooked.add(address);
		}
		run_one_combination(Level.FULL,"the selected address left alone, with the references on"+on,options,address,expectations_with_the_address_left_alone);

		/*
		 * A range of functions with the thunks refused. A range of any size runs into thunks on its way, and until now the refusal
		 * of the thunks was only ever asked of a thunk that was selected on purpose.
		 */
		options=create_the_options();
		if (options==null) { return; }
		options.isRangeFunctionsCheckBoxchecked=true;
		options.RangeFunctionsNum=25;
		options.RangeFunctionsRadioButtonFun.setSelected(true);
		options.isDoNotHookThunkFunctionscheckboxchecked=true;
		options.isDoNotHookExternalFunctionscheckboxchecked=true;
		options.isOutputReasonForHookGenCheckboxchecked=true;
		options.isGenerateScriptCheckboxchecked=true;
		run_one_combination(Level.FULL,"a range of twenty five functions with the thunks and the external ones refused"+on,options,address,new_expectations_for(true,null));

		/*
		 * A custom text that carries a quote of its own. The text is javascript that the plugin does not touch, and it is placed
		 * inside a block of other javascript, so a quote in it must not be able to swallow what follows.
		 */
		options=create_the_options();
		if (options==null) { return; }
		options.isIncludeCustomTextcheckboxchecked=true;
		options.IncludeCustomTextTextField.setText("console.log(\"a text with 'a quote' and a \\\\ backslash\");");
		options.isIncludeCustomTextAftercheckboxchecked=true;
		options.IncludeCustomTextAfterTextField.setText("console.log('and one with \\\"double quotes\\\" in it');");
		GeneratedScriptChecker.Expectations expectations_for_the_quoted_text=new_expectations_for(false,address);
		expectations_for_the_quoted_text.text_that_must_appear_somewhere="a text with 'a quote'";
		run_one_combination(Level.FULL,"a custom text that carries quotes and a backslash"+on,options,address,expectations_for_the_quoted_text);

		/*The reasons, with a regular expression that carries the characters that used to break the generated script*/
		options=create_the_options();
		if (options==null) { return; }
		options.isOutputReasonForHookGenCheckboxchecked=true;
		options.isFunctionRegexCheckBoxchecked=true;
		options.FunctionRegexTextField.setText(".*\"quoted\".*\\d.*");
		run_one_combination("a reason that carries a quote and a backslash"+on,options,address,new_expectations_for(false,null));

		/*The custom text, which is javascript that the user writes and the plugin has to place inside the hook*/
		options=create_the_options();
		if (options==null) { return; }
		options.isIncludeCustomTextcheckboxchecked=true;
		options.IncludeCustomTextTextField.setText("console.log('a custom line of the self test');");
		options.isIncludeCustomTextAftercheckboxchecked=true;
		options.IncludeCustomTextAfterTextField.setText("console.log('another custom line of the self test');");
		GeneratedScriptChecker.Expectations expectations_for_the_custom_text=new_expectations_for(false,address);
		expectations_for_the_custom_text.text_that_must_appear_somewhere="a custom line of the self test";
		run_one_combination(Level.MEDIUM,"the custom text before and after"+on,options,address,expectations_for_the_custom_text);

		/*The references, in both directions*/
		options=create_the_options();
		if (options==null) { return; }
		options.isReferencestoAddressCheckBoxchecked=true;
		options.isFunctionsReferencingAddressCheckBoxchecked=true;
		options.isReferencestoFunctionCheckboxchecked=true;
		options.isOutReferencesfromAddressCheckBoxchecked=true;
		run_one_combination(Level.MEDIUM,"the references to and from an address and a function"+on,options,address,new_expectations_for(false,null));

		options=create_the_options();
		if (options==null) { return; }
		options.isFunctionsReferencingFunctionCheckboxchecked=true;
		options.InFunctionReferenceDepthcomboBox.setSelectedIndex(1);	//depth two
		options.isOutReferencesfromFunctionCheckBoxchecked=true;
		options.OutFunctionReferenceDepthcomboBox.setSelectedIndex(1);
		run_one_combination(Level.FULL,"the incoming and the outgoing calls for a depth of two"+on,options,address,new_expectations_for(false,null));

		/*The ranges*/
		options=create_the_options();
		if (options==null) { return; }
		options.isRangeFunctionsCheckBoxchecked=true;
		options.RangeFunctionsNum=5;
		options.RangeFunctionsRadioButtonFun.setSelected(true);
		run_one_combination(Level.MEDIUM,"a range of five functions"+on,options,address,new_expectations_for(false,null));

		options=create_the_options();
		if (options==null) { return; }
		options.isRangeAddressesCheckBoxchecked=true;
		options.RangeAddressesNum=20;
		options.RangeAddressesRadioButtonInstr.setSelected(true);
		run_one_combination(Level.MEDIUM,"a range of twenty instructions"+on,options,address,new_expectations_for(false,null));

		/*---- the ones that only make sense at the beginning of a function ----*/
		if (representative_address.it_is_the_beginning_of_a_function.booleanValue()
				&& !representative_address.it_is_a_thunk.booleanValue() && !representative_address.it_is_external.booleanValue())
		{
			options=create_the_options();
			if (options==null) { return; }
			options.isCustomFunInterceptorHookOutputCheckboxchecked=true;
			options.CustomFunInterceptorHookOutputcomboBox.setSelectedIndex(2);	//Interceptor.replace()
			options.isIncludeFunParamNamescheckboxchecked=true;
			GeneratedScriptChecker.Expectations expectations_for_replace=new_expectations_for(false,address);
			expectations_for_replace.the_interceptor_replace_form_is_expected=true;
			run_one_combination("the Interceptor.replace form with the names of the parameters"+on,options,address,expectations_for_replace);

			/*
			 * The replacement, with a backtrace asked for in each of the two ways that matter.
			 * A replacement is entered at the beginning of the function it replaces, so both ways have to put a backtrace in
			 * it. The way of index 0 used to put none at all, because the code that writes the backtrace was told that a
			 * replacement is not the beginning of a function.
			 */
			int[] the_two_ways_of_the_backtrace={0,2};
			String[] names_of_the_two_ways={"at the beginnings of the functions","in every hook"};
			for (int i=0;i<the_two_ways_of_the_backtrace.length;i++)
			{
				options=create_the_options();
				if (options==null) { return; }
				options.isCustomFunInterceptorHookOutputCheckboxchecked=true;
				options.CustomFunInterceptorHookOutputcomboBox.setSelectedIndex(2);	//Interceptor.replace()
				options.isGenerateBacktraceCheckboxchecked=true;
				options.GenerateBacktracecomboBox.setSelectedIndex(the_two_ways_of_the_backtrace[i]);
				options.isIncludeTIDAndIndentationcheckboxchecked=true;
				options.isIncludeInterceptorTryCatchcheckboxchecked=true;
				GeneratedScriptChecker.Expectations expectations_for_the_replacement=new_expectations_for(false,address);
				expectations_for_the_replacement.the_interceptor_replace_form_is_expected=true;
				run_one_combination(Level.MEDIUM,"the Interceptor.replace form with a backtrace "+names_of_the_two_ways[i]+on,
						options,address,expectations_for_the_replacement);
			}

			/*
			 * The replacement together with everything that adds code inside it: the reasons, which are written as a marker
			 * and put in later, and the custom text of the user. The marker of the reasons is the one thing that must never
			 * survive, and the replacement is the form where it is written without an indentation of its own.
			 */
			options=create_the_options();
			if (options==null) { return; }
			options.isCustomFunInterceptorHookOutputCheckboxchecked=true;
			options.CustomFunInterceptorHookOutputcomboBox.setSelectedIndex(2);	//Interceptor.replace()
			options.isOutputReasonForHookGenCheckboxchecked=true;
			options.isIncludeCustomTextcheckboxchecked=true;
			options.IncludeCustomTextTextField.setText("console.log('before the original');");
			options.isIncludeCustomTextAftercheckboxchecked=true;
			options.IncludeCustomTextAfterTextField.setText("console.log('after the original');");
			options.isIncludeFunParamNamescheckboxchecked=true;
			GeneratedScriptChecker.Expectations expectations_for_the_replacement_with_the_reasons=new_expectations_for(false,address);
			expectations_for_the_replacement_with_the_reasons.the_interceptor_replace_form_is_expected=true;
			expectations_for_the_replacement_with_the_reasons.text_that_must_appear_somewhere="before the original";
			run_one_combination(Level.MEDIUM,"the Interceptor.replace form with the reasons and the custom text"+on,
					options,address,expectations_for_the_replacement_with_the_reasons);

			/*The replacement as a whole script, so that the prologue and the epilogue are written around it as well*/
			options=create_the_options();
			if (options==null) { return; }
			options.isCustomFunInterceptorHookOutputCheckboxchecked=true;
			options.CustomFunInterceptorHookOutputcomboBox.setSelectedIndex(2);	//Interceptor.replace()
			options.isGenerateScriptCheckboxchecked=true;
			GeneratedScriptChecker.Expectations expectations_for_the_replacement_script=new_expectations_for(true,address);
			expectations_for_the_replacement_script.the_interceptor_replace_form_is_expected=true;
			run_one_combination(Level.FULL,"the Interceptor.replace form as a whole script"+on,options,address,expectations_for_the_replacement_script);

			/*
			 * Everything that writes inside a hook, against each of the three forms of a function hook.
			 * This is the combination that asks what the options cannot be asked on their own: what becomes of the code of an
			 * option when the half of the hook it is written into is not there. The increase of the indentation is written into
			 * the onEnter and the decrease into the onLeave, the reasons and the backtrace go into the onEnter, and the text
			 * that the user asked to be placed last goes into the onLeave.
			 */
			int[] the_three_forms={0,1,2};
			String[] names_of_the_three_forms={"without an onEnter","without an onLeave","as an Interceptor.replace"};
			for (int index_of_the_form=0;index_of_the_form<the_three_forms.length;index_of_the_form++)
			{
				options=create_the_options();
				if (options==null) { return; }
				options.isCustomFunInterceptorHookOutputCheckboxchecked=true;
				options.CustomFunInterceptorHookOutputcomboBox.setSelectedIndex(the_three_forms[index_of_the_form]);
				options.isIncludeInterceptorTryCatchcheckboxchecked=true;
				options.isIncludeTIDAndIndentationcheckboxchecked=true;
				options.isGenerateBacktraceCheckboxchecked=true;
				options.GenerateBacktracecomboBox.setSelectedIndex(2);
				options.isCreateDataStructuresToLinkAddressesAndFunctionNamescheckboxchecked=true;
				options.isCreateDataStructureWithInterceptorAttachObjectscheckboxchecked=true;
				options.isOutputReasonForHookGenCheckboxchecked=true;
				options.isIncludeCustomTextcheckboxchecked=true;
				options.IncludeCustomTextTextField.setText("console.log('the custom text that goes first');");
				options.isIncludeCustomTextAftercheckboxchecked=true;
				options.IncludeCustomTextAfterTextField.setText("console.log('the custom text that goes last');");
				GeneratedScriptChecker.Expectations expectations_for_the_form=new_expectations_for(false,address);
				if (the_three_forms[index_of_the_form]==2)
				{
					expectations_for_the_form.the_interceptor_replace_form_is_expected=true;
				}
				if (the_three_forms[index_of_the_form]==0)
				{
					expectations_for_the_form.the_onEnter_is_expected_to_be_absent=true;
				}
				run_one_combination(Level.MEDIUM,"every option that writes inside a hook, on a hook "+names_of_the_three_forms[index_of_the_form]+on,
						options,address,expectations_for_the_form);
			}

			options=create_the_options();
			if (options==null) { return; }
			options.isCustomFunInterceptorHookOutputCheckboxchecked=true;
			options.CustomFunInterceptorHookOutputcomboBox.setSelectedIndex(0);	//without an onEnter()
			run_one_combination("a function hook without an onEnter"+on,options,address,new_expectations_for(false,address));

			/*
			 * A hook without an onEnter, with a backtrace asked for in every hook. The backtrace of a function hook is written
			 * inside the onEnter, so the right output here is a hook with no backtrace at all, and the checks have to know it.
			 */
			options=create_the_options();
			if (options==null) { return; }
			options.isCustomFunInterceptorHookOutputCheckboxchecked=true;
			options.CustomFunInterceptorHookOutputcomboBox.setSelectedIndex(0);	//without an onEnter()
			options.isGenerateBacktraceCheckboxchecked=true;
			options.GenerateBacktracecomboBox.setSelectedIndex(2);
			run_one_combination(Level.FULL,"a function hook without an onEnter, with a backtrace asked for"+on,options,address,new_expectations_for(false,address));

			options=create_the_options();
			if (options==null) { return; }
			options.isCustomFunInterceptorHookOutputCheckboxchecked=true;
			options.CustomFunInterceptorHookOutputcomboBox.setSelectedIndex(1);	//without an onLeave()
			run_one_combination(Level.MEDIUM,"a function hook without an onLeave"+on,options,address,new_expectations_for(false,address));

			options=create_the_options();
			if (options==null) { return; }
			options.isDoNotIncludeFunParamscheckboxchecked=true;
			run_one_combination(Level.MEDIUM,"a function hook that does not print the parameters"+on,options,address,new_expectations_for(false,address));

			options=create_the_options();
			if (options==null) { return; }
			options.isGenerateNormalAddressHooksForFunctionBeginningscheckboxchecked=true;
			run_one_combination(Level.MEDIUM,"a function beginning treated as an ordinary address"+on,options,address,new_expectations_for(false,address));
		}

		/*---- the ones that only make sense for a thunk or an external function ----*/
		if (representative_address.it_is_a_thunk.booleanValue())
		{
			options=create_the_options();
			if (options==null) { return; }
			options.isDoNotHookThunkFunctionscheckboxchecked=true;
			run_one_combination("a thunk that must not be hooked"+on,options,address,new_expectations_for(false,null));

			/*
			 * The same thunk, with the reporting of the destination of the computed calls switched on. A thunk is usually a
			 * computed jump, and this is the combination in which the two halves of the backpatching used to disagree and leave
			 * a marker inside the generated script.
			 */
			options=create_the_options();
			if (options==null) { return; }
			options.isDoNotHookThunkFunctionscheckboxchecked=true;
			options.isOutDynamicCallReferencesfromAddressCheckBoxchecked=true;
			run_one_combination("a thunk that must not be hooked, with the computed calls reported"+on,options,address,new_expectations_for(false,null));

			/*And the other direction: with the option off, a thunk is an ordinary function and it has to be hooked*/
			options=create_the_options();
			if (options==null) { return; }
			run_one_combination(Level.MEDIUM,"a thunk that is hooked because nothing refuses it"+on,options,address,new_expectations_for(false,address));
		}
		if (representative_address.it_is_external.booleanValue())
		{
			options=create_the_options();
			if (options==null) { return; }
			options.isDoNotHookExternalFunctionscheckboxchecked=true;
			run_one_combination(Level.MEDIUM,"an external function that must not be hooked"+on,options,address,new_expectations_for(false,null));
		}

		/*---- the ones that only make sense for a computed call ----*/
		if (representative_address.it_is_a_computed_call.booleanValue())
		{
			options=create_the_options();
			if (options==null) { return; }
			options.isOutDynamicCallReferencesfromAddressCheckBoxchecked=true;
			run_one_combination("the destination of a computed call"+on,options,address,new_expectations_for(false,address));

			options=create_the_options();
			if (options==null) { return; }
			options.isOutDynamicCallReferencesfromFunctionCheckBoxchecked=true;
			options.isOutputReasonForHookGenCheckboxchecked=true;
			run_one_combination(Level.MEDIUM,"every computed call of a function, with the reasons"+on,options,address,new_expectations_for(false,null));

			/*
			 * The destination of a computed call together with the two forms of a function hook. Careful: these only mean
			 * anything when the computed call really is at the beginning of a function, which is why the kind of the address
			 * is asked and not assumed.
			 */
			if (representative_address.it_is_the_beginning_of_a_function.booleanValue())
			{
				options=create_the_options();
				if (options==null) { return; }
				options.isOutDynamicCallReferencesfromAddressCheckBoxchecked=true;
				options.isCustomFunInterceptorHookOutputCheckboxchecked=true;
				options.CustomFunInterceptorHookOutputcomboBox.setSelectedIndex(2);
				run_one_combination(Level.MEDIUM,"the destination of a computed call inside an Interceptor.replace"+on,options,address,new_expectations_for(false,null));

				options=create_the_options();
				if (options==null) { return; }
				options.isOutDynamicCallReferencesfromAddressCheckBoxchecked=true;
				options.isCustomFunInterceptorHookOutputCheckboxchecked=true;
				options.CustomFunInterceptorHookOutputcomboBox.setSelectedIndex(0);
				run_one_combination(Level.MEDIUM,"the destination of a computed call in a hook without an onEnter"+on,options,address,new_expectations_for(false,null));
			}
		}
	}

	/*
	 * The combinations that do not belong to one address: they walk over every function, every symbol or the whole memory of
	 * the program. They are run once, whatever the number of addresses.
	 */
	protected void run_the_combinations_that_walk_the_whole_program()
	{

		Address address=this.representative_addresses.get(0).address;
		AdvancedHookOptionsDialog options;

		/*A regular expression that really matches something, so that the database can say which functions had to be hooked*/
		if (this.name_of_a_function_for_the_regular_expression!=null)
		{
			options=create_the_options();
			if (options==null) { return; }
			options.isFunctionRegexCheckBoxchecked=true;
			String regular_expression=java.util.regex.Pattern.quote(this.name_of_a_function_for_the_regular_expression);
			options.FunctionRegexTextField.setText(regular_expression);
			GeneratedScriptChecker.Expectations expectations=new_expectations_for(false,null);
			expectations.regex_of_function_names_that_must_be_hooked=regular_expression;
			run_one_combination(Level.FULL,"a regular expression that matches one function of the program",options,address,expectations);
		}

		/*The regular expression on the mangled names*/
		options=create_the_options();
		if (options==null) { return; }
		options.isFunctionMangledNameRegexCheckBoxchecked=true;
		options.FunctionMangledNameRegexTextField.setText("_Z.*");
		run_one_combination(Level.FULL,"a regular expression on the mangled names",options,address,new_expectations_for(false,null));

		/*The exported entry points, which the database can enumerate on its own*/
		options=create_the_options();
		if (options==null) { return; }
		options.isHookExportsCheckBoxchecked=true;
		GeneratedScriptChecker.Expectations expectations_for_the_exports=new_expectations_for(false,null);
		expectations_for_the_exports.every_exported_entry_point_must_be_hooked=true;
		run_one_combination(Level.MEDIUM,"every exported entry point",options,address,expectations_for_the_exports);

		/*The imported symbols, which are written by a piece of code of their own*/
		options=create_the_options();
		if (options==null) { return; }
		options.isHookImportsCheckBoxchecked=true;
		run_one_combination(Level.FULL,"every imported symbol",options,address,new_expectations_for(false,null));

		/*
		 * The three selectors that walk the whole program, all three switched on at once.
		 * They do not write their code in the same place: the one of the regular expression and the one of the exported entry
		 * points are written by the first hook of the batch, and the one of the imported symbols by the last, because its
		 * result is kept in the state of the generator until then. Two of them switched on together is the only way to find out
		 * that one has taken the place of another.
		 */
		options=create_the_options();
		if (options==null) { return; }
		options.isFunctionRegexCheckBoxchecked=true;
		options.FunctionRegexTextField.setText(".*init.*");
		options.isHookExportsCheckBoxchecked=true;
		options.isHookImportsCheckBoxchecked=true;
		options.isGenerateScriptCheckboxchecked=true;
		options.isIncludeInterceptorTryCatchcheckboxchecked=true;
		run_one_combination(Level.FULL,"the regular expression, the exported entry points and the imported symbols at once",options,address,new_expectations_for(true,null));

		/*
		 * The memory scan together with one of the ways of waiting for a library to be loaded, and with the mangled names on
		 * top. The scan and the prologue that waits both write code that runs before the hooks and both look at the modules of
		 * the process, so they have to be able to live next to each other.
		 */
		options=create_the_options();
		if (options==null) { return; }
		options.isMemoryScanPatternCheckBoxchecked=true;
		options.MemoryScanPatternTextField.setText(" 5b 5d [01001...] 8d 15 ");
		options.isFunctionMangledNameRegexCheckBoxchecked=true;
		options.FunctionMangledNameRegexTextField.setText("_ZN.*");
		options.isGenerateScriptCheckboxchecked=true;
		options.TypeofScriptGenerationcomboBox.setSelectedIndex(1);	//the dlopen method
		options.isIncludeTIDAndIndentationcheckboxchecked=true;
		options.isIncludeInterceptorTryCatchcheckboxchecked=true;
		run_one_combination(Level.FULL,"a memory scan and the mangled names inside a script that waits for a library",options,address,new_expectations_for(true,null));

		/*
		 * The imported symbols with the external functions refused. Every imported symbol is an external function, so these two
		 * options pull in opposite directions and what comes out of the pair is worth looking at.
		 */
		options=create_the_options();
		if (options==null) { return; }
		options.isHookImportsCheckBoxchecked=true;
		options.isDoNotHookExternalFunctionscheckboxchecked=true;
		options.isGenerateScriptCheckboxchecked=true;
		run_one_combination(Level.FULL,"the imported symbols with the external functions refused",options,address,new_expectations_for(true,null));

		/*Both regular expressions at once, the one on the names and the one on the mangled names*/
		options=create_the_options();
		if (options==null) { return; }
		options.isFunctionRegexCheckBoxchecked=true;
		options.FunctionRegexTextField.setText(".*_init$");
		options.isFunctionMangledNameRegexCheckBoxchecked=true;
		options.FunctionMangledNameRegexTextField.setText("_ZN.*");
		options.isOutputReasonForHookGenCheckboxchecked=true;
		options.isGenerateScriptCheckboxchecked=true;
		run_one_combination(Level.FULL,"both regular expressions at once",options,address,new_expectations_for(true,null));

		/*The memory scan, with a pattern that is valid and with one that is not*/
		options=create_the_options();
		if (options==null) { return; }
		options.isMemoryScanPatternCheckBoxchecked=true;
		options.MemoryScanPatternTextField.setText(" 5b 5d [01001...] 8d 15 ");
		run_one_combination(Level.MEDIUM,"a memory scan for a valid pattern, with spaces around it",options,address,new_expectations_for(false,address));

		options=create_the_options();
		if (options==null) { return; }
		options.isMemoryScanPatternCheckBoxchecked=true;
		options.MemoryScanPatternTextField.setText("this is not a pattern at all");
		run_one_combination(Level.MEDIUM,"a memory scan for a pattern that is not valid",options,address,new_expectations_for(false,address));

		/*Two addresses at once, which is what a selection does*/
		if (this.representative_addresses.size()>1)
		{
			options=create_the_options();
			if (options==null) { return; }
			options.isGenerateScriptCheckboxchecked=true;
			options.isOutputReasonForHookGenCheckboxchecked=true;
			ArrayList<Address> two_addresses=new ArrayList<Address>();
			two_addresses.add(this.representative_addresses.get(0).address);
			two_addresses.add(this.representative_addresses.get(1).address);
			GeneratedScriptChecker.Expectations expectations_for_two=new_expectations_for(true,null);
			expectations_for_two.addresses_that_must_be_hooked=two_addresses;
			run_one_combination_for_many_addresses("two addresses at once, as a selection does",options,two_addresses,expectations_for_two);
		}
	}

	/*----------------------------------------------------------------------------------------------------------------*/


	/*----------------------------------------------------------------------------------------------------------------*/

	/*
	 * A set of options with everything switched off. Careful: the dialog is also the object that carries the options, so
	 * building it builds swing components. When that cannot be done, the whole part of the self test that generates
	 * scripts is reported as skipped instead of bringing the tool down.
	 */
	protected AdvancedHookOptionsDialog create_the_options()
	{
		try {
			AdvancedHookOptionsDialog options=new AdvancedHookOptionsDialog(this.incoming_plugintool,this.current_program);
			/*Only this address is hooked unless a combination asks for more, which keeps the generated scripts small*/
			options.isHookThisAddressCheckBoxchecked=true;
			return options;
		}
		catch (Throwable t)
		{
			this.report.add_skipped_step("every combination that generates a script","the options object could not be built: "+t.toString());
			return null;
		}
	}

	/*
	 * Writes a generated script into a directory of its own under the temporary directory of the system, and returns the path
	 * of the file. A generated script can be megabytes long, so a path is a great deal more useful in a report than the text.
	 */
	protected String write_the_script_out(String name_of_the_combination,String script)
	{
		FileOutputStream stream=null;
		try {
			File directory=new File(System.getProperty("java.io.tmpdir"),"fridahookgenerator_selftest");
			directory.mkdirs();
			String name_of_the_file=name_of_the_combination.replaceAll("[^0-9a-zA-Z_]","_");
			if (name_of_the_file.length()>120)
			{
				name_of_the_file=name_of_the_file.substring(0,120);
			}
			File file=new File(directory,name_of_the_file+".js");
			stream=new FileOutputStream(file);
			stream.write(script.getBytes(StandardCharsets.UTF_8));
			stream.close();
			stream=null;
			return file.getAbsolutePath();
		}
		catch (Exception ex)
		{
			return "";	//not being able to write the script out is not a finding about the plugin
		}
		finally {
			if (stream!=null)
			{
				try { stream.close(); } catch (Exception ex) { }
			}
		}
	}

	/*
	 * Lists the options that were switched on for a combination, by looking at the fields of the object that carries them.
	 * Doing it this way means that an option that is added to the plugin appears here without anything being changed.
	 */
	protected String return_the_options_that_are_on(AdvancedHookOptionsDialog options)
	{
		StringBuffer retval=new StringBuffer(512);
		try {
			Field[] the_fields=AdvancedHookOptionsDialog.class.getFields();
			for (int i=0;i<the_fields.length;i++)
			{
				Field field=the_fields[i];
				if (!field.getName().startsWith("is") || !field.getType().equals(Boolean.class))
				{
					continue;
				}
				/*These two are not options of the hook generation, they are how the dialog was opened and whether it was accepted*/
				if (field.getName().equals("isOKpressed") || field.getName().equals("is_invoked_from_selecting_multiple_addresses"))
				{
					continue;
				}
				Object value=field.get(options);
				if (value!=null && ((Boolean)value).booleanValue())
				{
					retval.append((retval.length()>0?" , ":"")+field.getName());
				}
			}
			/*The combo boxes carry a choice that a boolean cannot express*/
			retval.append(" | the way of registering: "+options.TypeofScriptGenerationcomboBox.getSelectedIndex());
			retval.append(" , the form of a function hook: "+options.CustomFunInterceptorHookOutputcomboBox.getSelectedIndex());
			retval.append(" , the kind of backtrace: "+options.GenerateBacktracecomboBox.getSelectedIndex());
		}
		catch (Throwable t)
		{
			return "the options could not be listed: "+t.toString();
		}
		return retval.toString();
	}

	protected GeneratedScriptChecker.Expectations new_expectations_for(Boolean the_script_has_a_prologue,Address address_that_must_be_hooked)
	{
		GeneratedScriptChecker.Expectations retval=new GeneratedScriptChecker.Expectations();
		retval.the_script_has_a_prologue=the_script_has_a_prologue;
		/*
		 * Careful: an address that holds no instruction cannot be hooked by anything, so no combination may be told to expect a
		 * hook for it. What such an address is there to test is the opposite: that every combination refuses it and still writes
		 * something that makes sense instead of a broken script.
		 */
		if (address_that_must_be_hooked!=null
				&& this.current_program.getListing().getInstructionAt(address_that_must_be_hooked)!=null)
		{
			retval.addresses_that_must_be_hooked.add(address_that_must_be_hooked);
		}
		return retval;
	}

	/*
	 * Whether an option other than the one that hooks the selected address could arrive at that same address anyway.
	 * A function that calls itself refers to its own beginning, so the options that follow the references collect it even when
	 * the user did not ask for the address itself, and a check that demanded its absence would be wrong.
	 */
	protected Boolean can_another_option_arrive_at_this_address_as_well(Address address)
	{
		try {
			Function function_containing_the_address=this.current_program.getFunctionManager().getFunctionContaining(address);
			ReferenceIterator the_references=this.current_program.getReferenceManager().getReferencesTo(address);
			int how_many_were_seen=0;
			while (the_references!=null && the_references.hasNext() && how_many_were_seen<10000)
			{
				Reference reference=the_references.next();
				how_many_were_seen++;
				/*Careful: the entry points and not the objects, so that two handles on the same function cannot compare unequal*/
				Function function_the_reference_comes_from=this.current_program.getFunctionManager().getFunctionContaining(reference.getFromAddress());
				if (function_containing_the_address!=null && function_the_reference_comes_from!=null
						&& function_containing_the_address.getEntryPoint().equals(function_the_reference_comes_from.getEntryPoint()))
				{
					return true;	//something inside the same function points at it, so following the references reaches it
				}
			}
		}
		catch (Throwable t)
		{
			return true;	//when in doubt, do not demand the absence of anything
		}
		return false;
	}

	protected void run_one_combination(String name_of_the_combination,AdvancedHookOptionsDialog options,Address address,GeneratedScriptChecker.Expectations expectations)
	{
		run_one_combination(Level.LOW,name_of_the_combination,options,address,expectations);
	}

	/*
	 * A combination that only runs from a certain level upwards. The ones that walk over every function or every symbol of
	 * the program are the expensive ones, and they are the ones that are left out of the smaller levels.
	 */
	protected void run_one_combination(Level level_that_is_needed,String name_of_the_combination,AdvancedHookOptionsDialog options,Address address,GeneratedScriptChecker.Expectations expectations)
	{
		if (!the_level_is_at_least(level_that_is_needed).booleanValue())
		{
			this.how_many_combinations_were_skipped_because_of_the_level++;
			return;
		}
		ArrayList<Address> only_this_address=new ArrayList<Address>();
		only_this_address.add(address);
		run_one_combination_for_many_addresses(name_of_the_combination,options,only_this_address,expectations);
	}

	protected void run_one_combination_for_many_addresses(String name_of_the_combination,AdvancedHookOptionsDialog options,ArrayList<Address> addresses,GeneratedScriptChecker.Expectations expectations)
	{
		this.report.set_the_current_combination(name_of_the_combination);
		int how_many_errors_before=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR);
		int how_many_warnings_before=this.report.return_how_many_of_severity(SelfTestFinding.Severity.WARNING);

		String script="";
		try {
			/*
			 * The api wants the addresses as hexadecimal, without the name of the address space in front of them, so the
			 * offset is what is handed over.
			 */
			String list_of_the_addresses="";
			for (int i=0;i<addresses.size();i++)
			{
				if (i>0)
				{
					list_of_the_addresses+=",";
				}
				list_of_the_addresses+=Long.toHexString(addresses.get(i).getOffset());
			}
			FridaHookGeneratorAPIHandler api_handler=new FridaHookGeneratorAPIHandler(this.incoming_plugintool,this.current_program,list_of_the_addresses,options);
			script=api_handler.perform_hook_generation();
		}
		catch (Throwable t)
		{
			this.report.add_error("the generator threw",name_of_the_combination,
					"The generator threw while it was producing this combination",
					t.getClass().getName()+": "+t.getMessage(),0);
			this.report.add_summary_of_a_step(name_of_the_combination,1,0,"threw");
			this.report.set_the_current_combination("");
			return;
		}

		/*The first of the addresses is the one that the checks about the options reason about, as it is the one the options were aimed at*/
		Address seed_address=null;
		if (addresses.size()>0)
		{
			seed_address=addresses.get(0);
		}
		this.checker.check_the_generated_script(script,expectations,options,seed_address);

		int how_many_errors=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR)-how_many_errors_before;
		int how_many_warnings=this.report.return_how_many_of_severity(SelfTestFinding.Severity.WARNING)-how_many_warnings_before;

		/*
		 * A script that failed is written out, so that it can be read whole instead of through the few lines that a finding
		 * carries, and the options that were on are listed, so that the combination can be reproduced by hand.
		 */
		String extra_information=script.length()+" characters generated";
		if (how_many_errors>0 || how_many_warnings>0)
		{
			String where_the_script_was_written=write_the_script_out(name_of_the_combination,script);
			this.report.add_info("the scripts that failed","the file of a script",
					"The script of the combination \""+name_of_the_combination+"\" was written to "+where_the_script_was_written,
					"the options that were on: "+return_the_options_that_are_on(options));
			if (!where_the_script_was_written.equals(""))
			{
				extra_information+=" , written to "+where_the_script_was_written;
			}
		}
		this.report.add_summary_of_a_step(name_of_the_combination,how_many_errors,how_many_warnings,extra_information);
		this.report.set_the_current_combination("");
	}
}
