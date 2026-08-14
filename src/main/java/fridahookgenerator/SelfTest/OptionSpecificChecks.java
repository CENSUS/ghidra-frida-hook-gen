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

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Set;

import fridahookgenerator.AdvancedHookOptionsDialog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

/*
 * One group of checks for every option of the dialog.
 *
 * Every option of the plugin leaves a signature inside the generated script, and every one of those signatures can be
 * asked about in two directions: it has to be there when the option is on, and it has to be absent when the option is off.
 * The second direction is the one that catches an option that is applied when nobody asked for it, and it costs nothing,
 * because every combination that this self test runs has most of the options switched off.
 *
 * Where the database can work out the answer on its own, it is asked: how many functions call this one, how many
 * instructions follow this address, what are the names of the parameters of that function, which symbols are imported.
 * Those are the checks that can tell that a script is perfectly good javascript which hooks the wrong things.
 *
 * Careful: there are two different places to look for something. The constructs of the language (var, onEnter:,
 * Interceptor.attach() ) are looked for in the code, where the strings and the comments have been blanked out, so that a
 * word inside a message is never mistaken for code. Everything that the script only prints (a reason, a piece of custom
 * text, the name of a function inside a message) has to be looked for in the whole text instead.
 */
public class OptionSpecificChecks {

	protected Program current_program;
	protected SelfTestReport report;
	protected AdvancedHookOptionsDialog options;
	protected JavascriptTextAnalyzer analyzer;
	protected Address seed_address;
	protected String sanitized_name_of_the_program;
	protected String characters_allowed_in_variable_name="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";

	/*How many hooks the script installs, worked out once and reused by the checks that compare a count against it*/
	protected int how_many_hooks_the_script_installs;
	/*How many things at most to enumerate from the database for one check, which is what the level of the self test decides*/
	protected int how_many_things_to_enumerate_from_the_database=25;

	public OptionSpecificChecks(Program current_program,SelfTestReport report,AdvancedHookOptionsDialog options,JavascriptTextAnalyzer analyzer,Address seed_address,int how_many_things_to_enumerate_from_the_database)
	{
		this(current_program,report,options,analyzer,seed_address);
		this.how_many_things_to_enumerate_from_the_database=how_many_things_to_enumerate_from_the_database;
	}

	public OptionSpecificChecks(Program current_program,SelfTestReport report,AdvancedHookOptionsDialog options,JavascriptTextAnalyzer analyzer,Address seed_address)
	{
		this.current_program=current_program;
		this.report=report;
		this.options=options;
		this.analyzer=analyzer;
		this.seed_address=seed_address;
		this.sanitized_name_of_the_program=current_program.getName().replaceAll("[^"+this.characters_allowed_in_variable_name+"]","_");
		/*
		 * Careful: the hooks are counted by the declaration of their offset and not by the calls of the interceptor. Every
		 * hooked address declares exactly one offset, in both of the two forms that a hook can take, while the calls of the
		 * interceptor also come from the block that scans the memory for a pattern and from the block that hooks the
		 * imported symbols, neither of which is a hook of an address of the program.
		 */
		this.how_many_hooks_the_script_installs=analyzer.return_how_many_times_in_the_code("var offset_of_");
	}

	/*
	 * Whether the address that the options were aimed at was deliberately refused. A thunk or an external function that one
	 * of the two options refuses is not hooked on purpose, and the checks that demand a hook must not fire for it.
	 */
	/*The sentence that the script carries in place of the hook of the seed address, which depends on why it was refused*/
	protected String return_the_words_that_the_refusal_of_the_seed_writes()
	{
		if (this.current_program.getListing().getInstructionAt(this.seed_address)==null)
		{
			return ", not an instruction";
		}
		Function function_at_the_seed=this.current_program.getFunctionManager().getFunctionAt(this.seed_address);
		if (function_at_the_seed!=null && this.options.isDoNotHookThunkFunctionscheckboxchecked.booleanValue() && function_at_the_seed.isThunk())
		{
			return "is a thunk function, not hooking";
		}
		return "is an external function, not hooking";
	}

	/*
	 * Whether one of the options that refuse to hook something would refuse this address.
	 * The options that collect addresses do not know about the refusals, so a range or a set of references may perfectly well
	 * contain an address that the plugin then declines to hook, and a check that demands a hook for every address the option
	 * collected would report the two options doing exactly what they were told.
	 */
	protected Boolean would_an_option_refuse_to_hook(Address address)
	{
		if (address==null)
		{
			return true;
		}
		if (this.current_program.getListing().getInstructionAt(address)==null)
		{
			return true;
		}
		Function function_at_the_address=this.current_program.getFunctionManager().getFunctionAt(address);
		if (function_at_the_address==null)
		{
			return false;
		}
		if (this.options.isDoNotHookThunkFunctionscheckboxchecked.booleanValue() && function_at_the_address.isThunk())
		{
			return true;
		}
		if (this.options.isDoNotHookExternalFunctionscheckboxchecked.booleanValue() && function_at_the_address.isExternal())
		{
			return true;
		}
		return false;
	}

	/*
	 * Whether the script installs any hook at all.
	 * A script can legitimately install none: the address that was selected holds no instruction, or every address that the
	 * options collected was refused. An option that writes its code inside a hook then has nowhere to write it, so nothing may
	 * be demanded of it. This is the same rule as the one about the prologue and the two halves of a hook, one step further out.
	 */
	protected Boolean does_the_script_install_any_hook()
	{
		return Boolean.valueOf(this.how_many_hooks_the_script_installs>0);
	}

	/*
	 * Whether the script says that the replace form could not be used. The four sentences are the four reasons that the plugin
	 * has for refusing it, and it writes the one that applied in the place of the replacement.
	 */
	protected Boolean did_the_plugin_refuse_the_replace_form()
	{
		String text_of_the_script=this.analyzer.return_the_original_text();
		if (text_of_the_script.indexOf("variadic number of arguments, interceptor.replace not supported")>=0) { return true; }
		if (text_of_the_script.indexOf("has undefined type of return value")>=0) { return true; }
		if (text_of_the_script.indexOf("has an unaccepted return type")>=0) { return true; }
		if (text_of_the_script.indexOf("cannot be Interceptor.replace()'d as parameter at position")>=0) { return true; }
		return false;
	}

	protected Boolean was_the_seed_address_refused_on_purpose()
	{
		if (this.seed_address==null)
		{
			return false;
		}
		/*An address that holds no instruction is refused by everything, whatever the options say*/
		if (this.current_program.getListing().getInstructionAt(this.seed_address)==null)
		{
			return true;
		}
		Function function_at_the_seed=this.current_program.getFunctionManager().getFunctionAt(this.seed_address);
		if (function_at_the_seed==null)
		{
			return false;
		}
		if (this.options.isDoNotHookThunkFunctionscheckboxchecked.booleanValue() && function_at_the_seed.isThunk())
		{
			return true;
		}
		if (this.options.isDoNotHookExternalFunctionscheckboxchecked.booleanValue() && function_at_the_seed.isExternal())
		{
			return true;
		}
		return false;
	}

	/*
	 * Whether the script can be expected to contain a hook of the form that is written for the beginning of a function. It
	 * cannot when the address is not the beginning of one, and it cannot when the user asked for every function beginning to
	 * be treated as an ordinary address. The options that change the form of a function hook have nothing to check then.
	 */
	protected Boolean can_the_script_contain_a_function_hook()
	{
		if (this.seed_address==null || was_the_seed_address_refused_on_purpose().booleanValue())
		{
			return false;
		}
		if (this.options.isGenerateNormalAddressHooksForFunctionBeginningscheckboxchecked.booleanValue())
		{
			return false;
		}
		return Boolean.valueOf(this.current_program.getFunctionManager().getFunctionAt(this.seed_address)!=null);
	}

	public void run_all_the_checks_that_the_options_ask_for()
	{
		check_the_option_that_hooks_this_address();
		check_the_option_of_the_try_catch();
		check_the_option_of_the_thread_id_and_the_indentation();
		check_the_option_of_the_backtrace();
		check_the_option_of_the_reasons();
		check_the_option_of_the_script_and_the_way_it_registers();
		check_the_options_of_the_custom_text();
		check_the_options_about_the_parameters_of_the_functions();
		check_the_option_of_the_form_of_the_function_hooks();
		check_the_option_that_treats_a_function_beginning_as_an_address();
		check_the_option_of_the_dictionaries_of_names();
		check_the_option_of_the_dictionary_of_the_attach_objects();
		check_the_option_of_the_imports();
		check_the_option_of_the_exports();
		check_the_option_of_the_memory_scan();
		check_the_options_that_refuse_to_hook_something();
		check_the_options_of_the_references();
		check_the_options_of_the_ranges();
		check_the_options_of_the_computed_calls();
		check_the_options_of_the_regular_expressions();
	}

	/*
	 * The options that pick the functions to hook by matching their name. The database can work out which functions match,
	 * so every one of them has to be in the script.
	 */
	protected void check_the_options_of_the_regular_expressions()
	{
		String name_of_check="the options that pick the functions by their name";

		/*
		 * Careful: the option that asks a language model which functions are related to a category must never be switched on
		 * by the self test. It sends every function name of the program over the network, which costs time and money, and it
		 * would make the result of the self test depend on what a model answered.
		 */
		this.report.count_one_check_that_was_run();
		if (this.options.isAIChatFunctionRegexCheckBoxchecked.booleanValue())
		{
			this.report.add_warning(name_of_check,"the model was asked",
					"The self test switched on the option that asks a language model, which it must never do: it goes over the network and its answer is not repeatable",
					"switch that option off in the combination that was being run",0);
		}

		if (this.options.isFunctionRegexCheckBoxchecked.booleanValue())
		{
			String the_regular_expression=this.options.FunctionRegexTextField.getText();
			if (the_regular_expression!=null && !the_regular_expression.trim().equals(""))
			{
				java.util.regex.Pattern pattern=null;
				try {
					pattern=java.util.regex.Pattern.compile(the_regular_expression,java.util.regex.Pattern.CASE_INSENSITIVE);
				}
				catch (Exception ex)
				{
					pattern=null;	//the expression of the combination is not a valid one, which is not a finding about the plugin
				}
				if (pattern!=null)
				{
					int how_many_matched=0;
					FunctionIterator function_iterator=this.current_program.getListing().getFunctions(true);
					while (function_iterator!=null && function_iterator.hasNext() && how_many_matched<this.how_many_things_to_enumerate_from_the_database)
					{
						Function function=function_iterator.next();
						String name_of_the_function=function.getName(true).replace("\"","_");
						if (!pattern.matcher(name_of_the_function).matches())
						{
							continue;
						}
						how_many_matched++;
						if (this.current_program.getListing().getInstructionAt(function.getEntryPoint())==null)
						{
							continue;
						}
						expect_the_address_to_be_hooked(name_of_check,"a function whose name matched",function.getEntryPoint(),
								"The option that hooks the functions whose name matches a regular expression was on, and this one matches");
					}
					this.report.add_info(name_of_check,"how many names matched",
							how_many_matched+" functions of the database match the regular expression that was asked for","");
				}
			}
		}

		if (this.options.isFunctionMangledNameRegexCheckBoxchecked.booleanValue())
		{
			String the_regular_expression=this.options.FunctionMangledNameRegexTextField.getText();
			if (the_regular_expression!=null && !the_regular_expression.trim().equals(""))
			{
				java.util.regex.Pattern pattern=null;
				try {
					pattern=java.util.regex.Pattern.compile(the_regular_expression,java.util.regex.Pattern.CASE_INSENSITIVE);
				}
				catch (Exception ex)
				{
					pattern=null;
				}
				if (pattern!=null)
				{
					/*The same reasoning as the plugin uses: a symbol at the beginning of a function, whose name is a mangled one and matches*/
					int how_many_matched=0;
					FunctionIterator function_iterator=this.current_program.getListing().getFunctions(true);
					while (function_iterator!=null && function_iterator.hasNext() && how_many_matched<this.how_many_things_to_enumerate_from_the_database)
					{
						Function function=function_iterator.next();
						SymbolIterator symbol_iterator=this.current_program.getSymbolTable().getSymbolsAsIterator(function.getEntryPoint());
						Boolean a_mangled_name_matched=false;
						while (symbol_iterator!=null && symbol_iterator.hasNext())
						{
							String name_of_the_symbol=symbol_iterator.next().getName();
							if (!name_of_the_symbol.startsWith("_Z") && !name_of_the_symbol.startsWith("?"))
							{
								continue;	//not a mangled name
							}
							if (pattern.matcher(name_of_the_symbol).matches())
							{
								a_mangled_name_matched=true;
							}
						}
						if (!a_mangled_name_matched.booleanValue())
						{
							continue;
						}
						how_many_matched++;
						if (this.current_program.getListing().getInstructionAt(function.getEntryPoint())==null)
						{
							continue;
						}
						expect_the_address_to_be_hooked(name_of_check,"a function whose mangled name matched",function.getEntryPoint(),
								"The option that hooks the functions whose mangled name matches a regular expression was on, and this one matches");
					}
					this.report.add_info(name_of_check,"how many mangled names matched",
							how_many_matched+" functions of the database have a mangled name that matches the regular expression that was asked for","");
				}
			}
		}
	}

	/*================================================================================================================
	 * the little helpers that every group of checks is written with
	 *==============================================================================================================*/

	protected void expect_in_the_code(String name_of_check,String needle,String why)
	{
		this.report.count_one_check_that_was_run();
		if (this.analyzer.return_how_many_times_in_the_code(needle)==0)
		{
			this.report.add_error(name_of_check,"missing "+needle,why,"expected to find the code '"+needle+"' and it is nowhere in the script",0);
		}
	}

	protected void expect_not_in_the_code(String name_of_check,String needle,String why)
	{
		this.report.count_one_check_that_was_run();
		ArrayList<Integer> positions=this.analyzer.return_the_positions_in_the_code_of(needle);
		if (positions.size()>0)
		{
			this.report.add_error(name_of_check,"unexpected "+needle,why,
					"did not expect the code '"+needle+"' and found it "+positions.size()+" times, first at: "+this.analyzer.return_the_line_at_the_position(positions.get(0).intValue()),
					this.analyzer.return_the_line_number_of_the_position(positions.get(0).intValue()));
		}
	}

	protected void expect_anywhere(String name_of_check,String needle,String why)
	{
		this.report.count_one_check_that_was_run();
		if (this.analyzer.return_the_positions_anywhere_of(needle).size()==0)
		{
			this.report.add_error(name_of_check,"missing text "+needle,why,"expected to find the text '"+needle+"' and it is nowhere in the script",0);
		}
	}

	protected void expect_not_anywhere(String name_of_check,String needle,String why)
	{
		this.report.count_one_check_that_was_run();
		ArrayList<Integer> positions=this.analyzer.return_the_positions_anywhere_of(needle);
		if (positions.size()>0)
		{
			this.report.add_error(name_of_check,"unexpected text "+needle,why,
					"did not expect the text '"+needle+"' and found it "+positions.size()+" times",
					this.analyzer.return_the_line_number_of_the_position(positions.get(0).intValue()));
		}
	}

	protected void expect_the_count_in_the_code(String name_of_check,String needle,int how_many_were_expected,String why)
	{
		this.report.count_one_check_that_was_run();
		int how_many_there_are=this.analyzer.return_how_many_times_in_the_code(needle);
		if (how_many_there_are!=how_many_were_expected)
		{
			this.report.add_error(name_of_check,"count of "+needle,why,
					"expected '"+needle+"' to appear "+how_many_were_expected+" times and it appears "+how_many_there_are+" times",0);
		}
	}

	/*
	 * For the things that the generated script emits once per hook but that other blocks of the script emit as well. The
	 * block that scans the memory for a pattern, for instance, wraps its own scan in a try, so an exact count would report
	 * a problem that is not there as soon as two options are used together.
	 */
	protected void expect_at_least_the_count_in_the_code(String name_of_check,String needle,int how_many_at_least,String why)
	{
		this.report.count_one_check_that_was_run();
		int how_many_there_are=this.analyzer.return_how_many_times_in_the_code(needle);
		if (how_many_there_are<how_many_at_least)
		{
			this.report.add_error(name_of_check,"count of "+needle,why,
					"expected '"+needle+"' to appear at least "+how_many_at_least+" times and it appears "+how_many_there_are+" times",0);
		}
	}

	protected void expect_the_same_count_in_the_code(String name_of_check,String first_needle,String second_needle,String why)
	{
		this.report.count_one_check_that_was_run();
		int how_many_of_the_first=this.analyzer.return_how_many_times_in_the_code(first_needle);
		int how_many_of_the_second=this.analyzer.return_how_many_times_in_the_code(second_needle);
		if (how_many_of_the_first!=how_many_of_the_second)
		{
			this.report.add_error(name_of_check,"counts of "+first_needle+" and "+second_needle,why,
					"'"+first_needle+"' appears "+how_many_of_the_first+" times and '"+second_needle+"' appears "+how_many_of_the_second+" times, and they have to be the same",0);
		}
	}

	/*Whether the script hooks a given address, which is decided by looking for the offset that the plugin would compute for it*/
	protected Boolean does_the_script_hook_the_address(Address address)
	{
		long offset=address.getOffset()-this.current_program.getImageBase().getOffset();
		String hexadecimal="0x"+Long.toHexString(offset<0?-offset:offset);
		return Boolean.valueOf(this.analyzer.return_the_code_only_text().indexOf("="+hexadecimal+";")>=0);
	}

	protected void expect_the_address_to_be_hooked(String name_of_check,String signature,Address address,String why)
	{
		this.report.count_one_check_that_was_run();
		if (!does_the_script_hook_the_address(address).booleanValue())
		{
			this.report.add_error(name_of_check,signature,why,"the address "+address+" is not hooked by the script",0);
		}
	}

	protected void expect_the_address_not_to_be_hooked(String name_of_check,String signature,Address address,String why)
	{
		this.report.count_one_check_that_was_run();
		if (does_the_script_hook_the_address(address).booleanValue())
		{
			this.report.add_error(name_of_check,signature,why,"the address "+address+" is hooked by the script and it should not be",0);
		}
	}

	/*================================================================================================================
	 * one group of checks per option
	 *==============================================================================================================*/

	protected void check_the_option_that_hooks_this_address()
	{
		String name_of_check="the option that hooks this address";
		if (this.seed_address==null)
		{
			return;
		}
		if (this.options.isHookThisAddressCheckBoxchecked.booleanValue())
		{
			/*
			 * Careful: an address that one of the two options refuses is not hooked on purpose, and the script says so in a
			 * comment instead of hooking it. Demanding a hook for it would report the plugin doing exactly what it was told.
			 */
			if (was_the_seed_address_refused_on_purpose().booleanValue())
			{
				/*
				 * Careful: the plugin writes a different sentence for each reason it refuses an address, and only two of the three
				 * end with the words "not hooking". An address that holds no instruction is refused before any option is even
				 * looked at, and what the script says about it is ", not an instruction".
				 */
				expect_anywhere(name_of_check,return_the_words_that_the_refusal_of_the_seed_writes(),
						"The address was refused, so the script has to say so instead of hooking it");
				return;
			}

			expect_the_address_to_be_hooked(name_of_check,"the seed address",this.seed_address,
					"The option that hooks the current address was on, so that address has to be hooked");

			/*And the hook of an address is one of the three forms that the plugin writes*/
			this.report.count_one_check_that_was_run();
			int how_many_hooks_of_a_function=this.analyzer.return_how_many_times_in_the_code("onEnter:")
					+this.analyzer.return_how_many_times_in_the_code("onLeave:")
					+this.analyzer.return_how_many_times_in_the_code("new NativeCallback(");
			int how_many_hooks_of_an_address=this.analyzer.return_how_many_times_in_the_code("function function_to_call_when_code_reaches_");
			if (how_many_hooks_of_a_function+how_many_hooks_of_an_address==0)
			{
				this.report.add_error(name_of_check,"no hook of any form",
						"The script hooks an address but contains none of the three forms of hook that the plugin writes","",0)
						.with("the script contains an onEnter, an onLeave, a NativeCallback or a function_to_call_when_code_reaches","at least one of them","none of them")
						.at("the address "+this.seed_address);
			}
		}
	}

	protected void check_the_option_of_the_try_catch()
	{
		/*
		 * The try and the catch are written around the call of the interceptor of a hook, so a script that installs no hook at
		 * all carries neither of them, and that is right. Same rule as everywhere else: an option that writes inside or around a
		 * hook has nothing to write when there is no hook.
		 */
		if (this.options.isIncludeInterceptorTryCatchcheckboxchecked.booleanValue() && !does_the_script_install_any_hook().booleanValue())
		{
			return;
		}
		String name_of_check="the option of the try/catch around every hook";
		if (this.options.isIncludeInterceptorTryCatchcheckboxchecked.booleanValue())
		{
			expect_in_the_code(name_of_check,"var counter_for_successful_Interceptor_hooks","The counter of the successful hooks has to be declared");
			expect_in_the_code(name_of_check,"var counter_for_failed_Interceptor_hooks","The counter of the failed hooks has to be declared");
			expect_the_count_in_the_code(name_of_check,"var counter_for_successful_Interceptor_hooks",1,"The counter has to be declared exactly once, no matter how many hooks there are");
			expect_in_the_code(name_of_check,"try {","Every hook has to be wrapped in a try");
			expect_in_the_code(name_of_check,"catch(error)","Every try has to have its catch");
			/*
			 * Every hook is wrapped, so there is at least one try for every hook. It is not an exact count, because other
			 * blocks of the generated script wrap themselves in a try as well.
			 */
			expect_at_least_the_count_in_the_code(name_of_check,"try {",this.how_many_hooks_the_script_installs,"There has to be a try for every hook that is installed");
			/*The two counters are increased exactly once per hook, by the very same piece of the generator, so these counts are exact*/
			expect_the_count_in_the_code(name_of_check,"counter_for_successful_Interceptor_hooks++",this.how_many_hooks_the_script_installs,"Every hook that succeeds has to increase the counter, once each");
			expect_the_count_in_the_code(name_of_check,"counter_for_failed_Interceptor_hooks++",this.how_many_hooks_the_script_installs,"Every hook that fails has to increase the counter, once each");
			expect_the_same_count_in_the_code(name_of_check,"counter_for_successful_Interceptor_hooks++","catch(error)","A hook that counts its success without a catch that counts its failure means the wrapping was only half written");
			expect_anywhere(name_of_check,"Successful Interceptor hooks:","The totals have to be printed at the end");
		}
		else
		{
			expect_not_in_the_code(name_of_check,"counter_for_successful_Interceptor_hooks","The option was off, so no counter of the hooks has to be declared");
			expect_not_in_the_code(name_of_check,"catch(error)","The option was off, so no hook has to be wrapped in a try");
		}
	}

	/*
	 * Three questions that most of the checks below have to ask before they demand anything.
	 *
	 * Careful: an option being on does not mean that its code is in the script. Half of the options write into the prologue,
	 * which only exists when a whole script was asked for and not a snippet, and another half write into the onEnter or into
	 * the onLeave of a function hook, either of which the user can ask to be left out. A check that demands the code of an
	 * option without asking these questions first reports scripts that are perfectly right, which is what several of the
	 * checks here used to do as soon as two options were switched on at the same time.
	 */
	protected Boolean the_script_carries_a_prologue()
	{
		return this.options.isGenerateScriptCheckboxchecked;
	}

	protected Boolean the_onEnter_was_asked_to_be_absent()
	{
		return Boolean.valueOf(this.options.isCustomFunInterceptorHookOutputCheckboxchecked.booleanValue()
				&& this.options.CustomFunInterceptorHookOutputcomboBox.getSelectedIndex()==0);
	}

	protected Boolean the_onLeave_was_asked_to_be_absent()
	{
		return Boolean.valueOf(this.options.isCustomFunInterceptorHookOutputCheckboxchecked.booleanValue()
				&& this.options.CustomFunInterceptorHookOutputcomboBox.getSelectedIndex()==1);
	}

	/*
	 * The general rule that follows from the two questions above, and the one that most of the checks here need.
	 *
	 * A hook that was asked to have no onEnter, or no onLeave, or a function beginning that the user asked to be treated as an
	 * ordinary address, is a hook with a half of it deliberately taken away. Every option whose code has to live in the half
	 * that went away loses its effect, and that is the intended consequence of asking for such a hook, not a defect of the
	 * generator: the reasons and the text that goes first are written into the onEnter, the text that goes last and the value
	 * that was returned into the onLeave, the indentation of the log goes up in the one and down in the other, and an ordinary
	 * address hook has neither of the two halves and none of what being a function brings with it.
	 *
	 * So a check must never demand, of such a hook, the code of an option that needs both halves, and must never demand that
	 * two things which are written one into each half still add up. What it can still demand is everything that lives in the
	 * half that is there, which is what the checks below and the ones of PerHookChecks keep asking for.
	 */
	protected Boolean a_half_of_the_hook_was_asked_to_be_taken_away()
	{
		return Boolean.valueOf(the_onEnter_was_asked_to_be_absent().booleanValue()
				|| the_onLeave_was_asked_to_be_absent().booleanValue()
				|| this.options.isGenerateNormalAddressHooksForFunctionBeginningscheckboxchecked.booleanValue());
	}

	protected void check_the_option_of_the_thread_id_and_the_indentation()
	{
		String name_of_check="the option of the thread identifier and the indentation";
		if (this.options.isIncludeTIDAndIndentationcheckboxchecked.booleanValue())
		{
			/*All four of these are written into the prologue, so a snippet uses them without carrying them, on purpose*/
			if (the_script_carries_a_prologue().booleanValue())
			{
				expect_in_the_code(name_of_check,"var dict_with_thread_indentation_levels","The dictionary of the levels has to be declared");
				expect_in_the_code(name_of_check,"function tid_and_indent","The function that builds the prefix has to be declared");
				expect_in_the_code(name_of_check,"function increase_indent","The function that increases the indentation has to be declared");
				expect_in_the_code(name_of_check,"function decrease_indent","The function that decreases the indentation has to be declared");
				expect_in_the_code(name_of_check,"Process.getCurrentThreadId()","The identifier of the thread has to be asked for");
			}
			/*The prefix is written into the messages of the hooks, so a script without a single hook carries none*/
			if (does_the_script_install_any_hook().booleanValue())
			{
				expect_in_the_code(name_of_check,"tid_and_indent(this)","Every message has to carry the prefix of the thread");
			}
			/*Every message of every hook carries the prefix, so there are at least as many uses of it as there are hooks*/
			this.report.count_one_check_that_was_run();
			int how_many_prefixes=this.analyzer.return_how_many_times_in_the_code("tid_and_indent(this)");
			if (this.how_many_hooks_the_script_installs>0 && how_many_prefixes<this.how_many_hooks_the_script_installs)
			{
				this.report.add_error(name_of_check,"not every hook carries the prefix",
						"The prefix of the thread is used fewer times than there are hooks, so some messages do not carry it",
						how_many_prefixes+" uses of the prefix for "+this.how_many_hooks_the_script_installs+" hooks",0);
			}
			/*
			 * The indentation goes up when a function is entered and down when it is left, so the two have to be balanced.
			 * Careful: the increase is written into the onEnter and the decrease into the onLeave, so this is exactly one of the
			 * things that a hook which was asked to give up a half of itself cannot be expected to keep. Asking for a hook
			 * without an onLeave is asking for the increase without the decrease, and the drifting indentation that follows is
			 * the consequence of that request.
			 */
			if (!a_half_of_the_hook_was_asked_to_be_taken_away().booleanValue())
			{
				expect_the_same_count_in_the_code(name_of_check,"increase_indent()","decrease_indent()",
						"The indentation is increased and decreased the same number of times, otherwise it drifts for ever");
			}
		}
		else
		{
			expect_not_in_the_code(name_of_check,"tid_and_indent","The option was off, so no message has to carry the prefix of the thread");
			expect_not_in_the_code(name_of_check,"dict_with_thread_indentation_levels","The option was off, so the dictionary of the levels has to be absent");
		}
	}

	protected void check_the_option_of_the_backtrace()
	{
		String name_of_check="the option of the backtrace";
		if (!this.options.isGenerateBacktraceCheckboxchecked.booleanValue())
		{
			expect_not_in_the_code(name_of_check,"Thread.backtrace","The option was off, so no backtrace has to be asked for");
			return;
		}

		/*
		 * Never null, whatever the way and whatever the hook. Passing null does not tell frida "there is no context", it tells
		 * it to unwind from wherever the javascript happens to be, which is inside frida's own trampoline, so the accurate
		 * backtracer stops early and the caller is missing from the result.
		 */
		expect_not_in_the_code(name_of_check,"Thread.backtrace(null",
				"The context of the hooked thread has to be handed to the backtracer, otherwise it unwinds from the wrong place");

		/*
		 * Careful: whether a backtrace has to be present at all is not a question that can be answered by looking at the whole
		 * script, and it used to be asked here, which is how this check reported scripts that were perfectly right. It depends
		 * on the form of each hook: the first two ways only cover the beginnings of the functions, the backtrace of a function
		 * hook is written inside its onEnter and disappears with it, and a replacement always counts as a function beginning.
		 * PerHookChecks knows the form of every hook it looks at, so it is the one that demands the line. What is left here is
		 * everything that has to hold once the line is somewhere in the script.
		 */
		if (this.analyzer.return_the_code_only_text().indexOf("Thread.backtrace")<0)
		{
			return;
		}

		expect_in_the_code(name_of_check,"Thread.backtrace(this.context","The context of the hooked thread has to be handed to the backtracer");
		expect_in_the_code(name_of_check,"DebugSymbol.fromAddress","The addresses of the backtrace have to be turned into symbols");
		int index_of_the_way=this.options.GenerateBacktracecomboBox.getSelectedIndex();
		if (index_of_the_way==0 || index_of_the_way==2)
		{
			expect_in_the_code(name_of_check,"Backtracer.ACCURATE","The accurate backtracer was asked for");
			expect_not_in_the_code(name_of_check,"Backtracer.FUZZY","The accurate backtracer was asked for, so the fuzzy one has to be absent");
		}
		else
		{
			expect_in_the_code(name_of_check,"Backtracer.FUZZY","The fuzzy backtracer was asked for");
			expect_not_in_the_code(name_of_check,"Backtracer.ACCURATE","The fuzzy backtracer was asked for, so the accurate one has to be absent");
		}
	}

	protected void check_the_option_of_the_reasons()
	{
		String name_of_check="the option that prints the reasons of the hooking";
		if (this.options.isOutputReasonForHookGenCheckboxchecked.booleanValue())
		{
			expect_not_anywhere(name_of_check,"PLACEHOLDER_FOR_REASONS_FOR_HOOKING_","Every marker of the reasons has to have been replaced by the reasons themselves");
			if (!does_the_script_install_any_hook().booleanValue())
			{
				return;	//no hook was installed, so there is nothing that could carry a reason
			}
			/*
			 * The message of the reasons of a function hook is written inside its onEnter, so a hook that was asked to have no
			 * onEnter carries no reasons and that is right. Which hooks have to carry them is decided in PerHookChecks, where
			 * the form of each hook is known.
			 */
			if (the_onEnter_was_asked_to_be_absent().booleanValue())
			{
				return;
			}
			expect_anywhere(name_of_check,"Reasons for hooking:","The reasons have to be printed");
			/*There is one message of reasons for every hook*/
			this.report.count_one_check_that_was_run();
			int how_many_messages_of_reasons=this.analyzer.return_the_positions_anywhere_of("Reasons for hooking:").size();
			if (this.how_many_hooks_the_script_installs>0 && how_many_messages_of_reasons<this.how_many_hooks_the_script_installs)
			{
				this.report.add_error(name_of_check,"not every hook prints its reasons",
						"There are fewer messages of reasons than there are hooks",
						how_many_messages_of_reasons+" messages for "+this.how_many_hooks_the_script_installs+" hooks",0);
			}
			/*No single message carries more reasons than the user asked for*/
			check_that_no_message_of_reasons_is_longer_than_asked(name_of_check);
		}
		else
		{
			expect_not_anywhere(name_of_check,"Reasons for hooking:","The option was off, so no reason has to be printed");
		}
	}

	protected void check_that_no_message_of_reasons_is_longer_than_asked(String name_of_check)
	{
		this.report.count_one_check_that_was_run();
		int how_many_were_asked_for=10;
		try {
			how_many_were_asked_for=Integer.parseInt(this.options.ReasonForHookGenAmountcomboBox.getItemAt(this.options.ReasonForHookGenAmountcomboBox.getSelectedIndex()));
		}
		catch (Exception ex)
		{
			return;
		}
		String whole_text=this.analyzer.return_the_original_text();
		ArrayList<Integer> positions=this.analyzer.return_the_positions_anywhere_of("Reasons for hooking:");
		for (int i=0;i<positions.size();i++)
		{
			int position=positions.get(i).intValue();
			int end_of_the_line=whole_text.indexOf("\n",position);
			if (end_of_the_line<0)
			{
				end_of_the_line=whole_text.length();
			}
			String text_of_the_message=whole_text.substring(position,end_of_the_line);
			/*The reasons of one message are separated by a marker of three hashes*/
			int how_many_separators=0;
			int position_of_a_separator=text_of_the_message.indexOf("###");
			while (position_of_a_separator>=0)
			{
				how_many_separators++;
				position_of_a_separator=text_of_the_message.indexOf("###",position_of_a_separator+3);
			}
			if (how_many_separators+1>how_many_were_asked_for && text_of_the_message.indexOf(", ... ")<0)
			{
				this.report.add_error(name_of_check,"too many reasons in one message",
						"A message carries more reasons than the number that was asked for, and it does not end with the mark that says that the rest were left out",
						"asked for "+how_many_were_asked_for+" and the message carries "+(how_many_separators+1),
						this.analyzer.return_the_line_number_of_the_position(position));
			}
		}
	}

	protected void check_the_option_of_the_script_and_the_way_it_registers()
	{
		String name_of_check="the option that generates a whole script";
		if (!this.options.isGenerateScriptCheckboxchecked.booleanValue())
		{
			expect_not_in_the_code(name_of_check,"function start_timer_for_intercept","A snippet was asked for, so it must not carry the prologue of the default method");
			expect_not_in_the_code(name_of_check,"Process.attachModuleObserver","A snippet was asked for, so it must not carry the prologue of the observer");
			expect_not_in_the_code(name_of_check,"Interceptor.flush()","A snippet was asked for, so it must not flush the interceptors on its own");
			return;
		}

		expect_in_the_code(name_of_check,"var module_name_"+this.sanitized_name_of_the_program,"Every script declares the name of the module that it hooks");
		expect_the_count_in_the_code(name_of_check,"Interceptor.flush()",1,"A script flushes the interceptors exactly once");

		int index_of_the_method=this.options.TypeofScriptGenerationcomboBox.getSelectedIndex();
		if (index_of_the_method==0)
		{
			expect_in_the_code(name_of_check,"function start_timer_for_intercept","The default method waits with a timer");
			expect_in_the_code(name_of_check,"setTimeout(","The default method waits with a timer");
			expect_anywhere(name_of_check,"2000","The default method waits for two seconds");
			expect_not_in_the_code(name_of_check,"function register_interceptors","The default method does not wait for a library to be loaded");
			expect_not_in_the_code(name_of_check,"Process.attachModuleObserver","The default method does not use the observer of the modules");
		}
		if (index_of_the_method==1)
		{
			expect_in_the_code(name_of_check,"function extract_libname_from_dlopen_arg","The dlopen method reads the name of the library out of the argument");
			expect_in_the_code(name_of_check,"function do_the_dlopen_interception","The dlopen method hooks the loader");
			expect_in_the_code(name_of_check,"function register_interceptors","The dlopen method registers the hooks when the library appears");
			expect_in_the_code(name_of_check,"readCString()","The argument of dlopen is a C string");
			expect_anywhere(name_of_check,"dlopen","The exports of the loader are looked for by name");
			expect_not_in_the_code(name_of_check,"function start_timer_for_intercept","The dlopen method does not wait with a timer");
			expect_in_the_code(name_of_check,"function does_module_name_match_the_wanted_one_"+this.sanitized_name_of_the_program,"The comparison of the name of the module has to be emitted by the prologue that uses it");
		}
		if (index_of_the_method==2)
		{
			expect_in_the_code(name_of_check,"function extract_libname_from_loadlibrary_arg","The LoadLibrary method reads the name of the library out of the argument");
			expect_in_the_code(name_of_check,"function do_the_loadlibrary_interception","The LoadLibrary method hooks the loader");
			expect_in_the_code(name_of_check,"readAnsiString()","LoadLibraryA takes a narrow string");
			expect_in_the_code(name_of_check,"readUtf16String()","LoadLibraryW takes a wide string");
			expect_anywhere(name_of_check,"LoadLibrary","The exports of the loader are looked for by name");
			expect_in_the_code(name_of_check,"function does_module_name_match_the_wanted_one_"+this.sanitized_name_of_the_program,"The comparison of the name of the module has to be emitted by the prologue that uses it");
		}
		if (index_of_the_method==3)
		{
			expect_in_the_code(name_of_check,"Process.attachModuleObserver","The observer method watches the modules that are loaded");
			expect_in_the_code(name_of_check,"onAdded(","The observer is told when a module appears");
			expect_in_the_code(name_of_check,"onRemoved(","The observer is told when a module goes away");
			expect_in_the_code(name_of_check,"function intercept_identified_module_"+this.sanitized_name_of_the_program,"The observer method registers the hooks in a function of its own");
			expect_not_in_the_code(name_of_check,"function start_timer_for_intercept","The observer method does not wait with a timer");
			expect_in_the_code(name_of_check,"function does_module_name_match_the_wanted_one_"+this.sanitized_name_of_the_program,"The comparison of the name of the module has to be emitted by the prologue that uses it");
		}
		/*Whatever the method, the comparison of the names of the modules must never be tolerant outside of Windows*/
		if (index_of_the_method>=1)
		{
			expect_in_the_code(name_of_check,"Process.platform","The tolerance that only Windows needs has to be behind a check of the platform");
		}
	}

	protected void check_the_options_of_the_custom_text()
	{
		String name_of_check="the options that add a custom text inside the hooks";
		if (!does_the_script_install_any_hook().booleanValue())
		{
			return;	//the text goes inside a hook, and this script has none
		}
		if (this.options.isIncludeCustomTextcheckboxchecked.booleanValue())
		{
			String text_that_was_asked_for=this.options.IncludeCustomTextTextField.getText();
			/*The text that goes first is written into the onEnter, so a hook without one cannot carry it*/
			if (text_that_was_asked_for!=null && !text_that_was_asked_for.trim().equals("")
					&& !the_onEnter_was_asked_to_be_absent().booleanValue())
			{
				expect_anywhere(name_of_check,text_that_was_asked_for,"The custom text that goes before has to be inside the script");
				/*It goes into every hook, so it appears at least as many times as there are hooks*/
				this.report.count_one_check_that_was_run();
				int how_many_times=this.analyzer.return_the_positions_anywhere_of(text_that_was_asked_for).size();
				if (this.how_many_hooks_the_script_installs>0 && how_many_times<this.how_many_hooks_the_script_installs)
				{
					this.report.add_error(name_of_check,"the custom text is not in every hook",
							"The custom text appears fewer times than there are hooks",
							how_many_times+" times for "+this.how_many_hooks_the_script_installs+" hooks",0);
				}
			}
		}
		if (this.options.isIncludeCustomTextAftercheckboxchecked.booleanValue())
		{
			String text_that_was_asked_for=this.options.IncludeCustomTextAfterTextField.getText();
			/*The text that goes last is written into the onLeave, so a hook without one cannot carry it*/
			if (text_that_was_asked_for!=null && !text_that_was_asked_for.trim().equals("")
					&& !the_onLeave_was_asked_to_be_absent().booleanValue())
			{
				expect_anywhere(name_of_check,text_that_was_asked_for,"The custom text that goes after has to be inside the script");
			}
		}
	}

	protected void check_the_options_about_the_parameters_of_the_functions()
	{
		String name_of_check="the options about the parameters of the functions";
		Function function_at_the_seed=null;
		if (this.seed_address!=null)
		{
			function_at_the_seed=this.current_program.getFunctionManager().getFunctionAt(this.seed_address);
		}

		if (this.options.isDoNotIncludeFunParamscheckboxchecked.booleanValue())
		{
			expect_not_anywhere(name_of_check,"args[0]=","The option that refuses to print the parameters was on, so no parameter has to be printed");
		}

		/*
		 * The names of the parameters are declared inside the onEnter of a function hook, or in the signature of the callback of
		 * a replacement, so a hook that was asked to have no onEnter has nowhere to declare them. Same rule as everywhere else:
		 * the option loses its effect together with the half of the hook that it writes into.
		 */
		if (this.options.isIncludeFunParamNamescheckboxchecked.booleanValue() && can_the_script_contain_a_function_hook().booleanValue()
				&& !the_onEnter_was_asked_to_be_absent().booleanValue()
				&& function_at_the_seed!=null && function_at_the_seed.getParameterCount()>0)
		{
			/*The names that the script uses have to be the names that the database has for the parameters of that function*/
			Boolean at_least_one_name_was_found=false;
			for (int i=0;i<function_at_the_seed.getParameterCount();i++)
			{
				Parameter parameter=function_at_the_seed.getParameter(i);
				if (parameter==null)
				{
					continue;
				}
				String sanitized_name_of_the_parameter=parameter.getName().replaceAll("[^"+this.characters_allowed_in_variable_name+"]","_");
				if (this.analyzer.return_how_many_times_in_the_code("arg_"+sanitized_name_of_the_parameter)>0)
				{
					at_least_one_name_was_found=true;
				}
			}
			this.report.count_one_check_that_was_run();
			if (!at_least_one_name_was_found.booleanValue())
			{
				this.report.add_error(name_of_check,"the names of the parameters are not the ones of the database",
						"The names of the parameters were asked for, but not one of the names that the database has for the parameters of the hooked function appears in the script",
						"the function "+function_at_the_seed.getName()+" has "+function_at_the_seed.getParameterCount()+" parameters",0);
			}
		}
	}

	protected void check_the_option_of_the_form_of_the_function_hooks()
	{
		String name_of_check="the option that changes the form of a function hook";
		if (!this.options.isCustomFunInterceptorHookOutputCheckboxchecked.booleanValue())
		{
			return;
		}
		/*
		 * Careful: these options only change the shape of a hook that sits on the beginning of a function. When the address is
		 * in the middle of one, the plugin writes a hook for an ordinary address and none of these options apply to it, so
		 * there is nothing here to check.
		 */
		if (!can_the_script_contain_a_function_hook().booleanValue())
		{
			return;
		}

		int index_of_the_form=this.options.CustomFunInterceptorHookOutputcomboBox.getSelectedIndex();
		if (index_of_the_form==0)
		{
			expect_not_in_the_code(name_of_check,"onEnter:","The form without an onEnter was asked for");
			expect_in_the_code(name_of_check,"onLeave:","The form without an onEnter still has its onLeave");
		}
		if (index_of_the_form==1)
		{
			expect_in_the_code(name_of_check,"onEnter:","The form without an onLeave still has its onEnter");
			expect_not_in_the_code(name_of_check,"onLeave:","The form without an onLeave was asked for");
		}
		if (index_of_the_form==2)
		{
			/*
			 * Careful: the plugin refuses the replace form for a function it cannot build a prototype for, and writes a comment
			 * saying which of the reasons applied. A function with a variadic number of arguments is the common one, and there is
			 * no way to hand those to a NativeFunction, so falling back to attaching is the right thing and not a defect.
			 */
			if (did_the_plugin_refuse_the_replace_form().booleanValue())
			{
				return;
			}
			expect_in_the_code(name_of_check,"Interceptor.replace(","The form that replaces the function was asked for");
			expect_in_the_code(name_of_check,"new NativeFunction(","The original function has to be kept, so that the replacement can call it");
			expect_in_the_code(name_of_check,"new NativeCallback(function(","The callback has to be a normal function, so that frida binds the invocation context to it");
			expect_not_in_the_code(name_of_check,"new NativeCallback((","The callback must not be an arrow function, it would have no context of its own");
			expect_in_the_code(name_of_check,"var retval=NativeFunction_of_","The replacement has to call the original function");
		}
	}

	protected void check_the_option_that_treats_a_function_beginning_as_an_address()
	{
		String name_of_check="the option that treats a function beginning as an ordinary address";
		if (!this.options.isGenerateNormalAddressHooksForFunctionBeginningscheckboxchecked.booleanValue())
		{
			return;
		}
		if (was_the_seed_address_refused_on_purpose().booleanValue())
		{
			return;	//nothing was hooked at all, there is no form to check
		}
		expect_not_in_the_code(name_of_check,"onEnter:","No function hook has to be written when every address is treated as an ordinary one");
		expect_not_in_the_code(name_of_check,"onLeave:","No function hook has to be written when every address is treated as an ordinary one");
		expect_in_the_code(name_of_check,"function function_to_call_when_code_reaches_","Every hook has to be of the form that an ordinary address gets");
	}

	protected void check_the_option_of_the_dictionaries_of_names()
	{
		String name_of_check="the option of the dictionaries that link the addresses with the names";
		if (this.options.isCreateDataStructuresToLinkAddressesAndFunctionNamescheckboxchecked.booleanValue())
		{
			/*The five declarations belong to the prologue, and a snippet is pasted into a script that already has them*/
			if (the_script_carries_a_prologue().booleanValue())
			{
				expect_in_the_code(name_of_check,"var dict_from_current_addresses_to_function_names","The dictionary of the names has to be declared");
				expect_in_the_code(name_of_check,"var dict_from_function_names_to_function_start_addresses","The dictionary of the beginnings has to be declared");
				expect_in_the_code(name_of_check,"var dict_from_current_addresses_to_function_start_addresses","The dictionary from an address to a beginning has to be declared");
				expect_in_the_code(name_of_check,"var dict_from_function_start_addresses_to_function_names","The dictionary from a beginning to a name has to be declared");
				expect_in_the_code(name_of_check,"var current_function_start_address","The variable that holds the beginning of the current function has to be declared");
			}
			/*Every hook writes itself into the dictionary, so a script without a hook writes nothing into it*/
			if (does_the_script_install_any_hook().booleanValue())
			{
				expect_in_the_code(name_of_check,"dict_from_current_addresses_to_function_names[","Every hook has to write itself into the dictionary");
			}
			/*Every hook writes one entry, so there are at least as many as there are hooks*/
			this.report.count_one_check_that_was_run();
			int how_many_entries=this.analyzer.return_how_many_times_in_the_code("dict_from_current_addresses_to_function_names[");
			if (this.how_many_hooks_the_script_installs>0 && how_many_entries<this.how_many_hooks_the_script_installs)
			{
				this.report.add_error(name_of_check,"not every hook is in the dictionary",
						"There are fewer entries in the dictionary of the names than there are hooks",
						how_many_entries+" entries for "+this.how_many_hooks_the_script_installs+" hooks",0);
			}
			/*The name that the script writes for the seed address has to be the one that the database has*/
			if (this.seed_address!=null)
			{
				Function function_at_the_seed=this.current_program.getFunctionManager().getFunctionAt(this.seed_address);
				if (function_at_the_seed!=null)
				{
					String sanitized_name=function_at_the_seed.getName(true).replaceAll("[^"+this.characters_allowed_in_variable_name+"]","_");
					expect_anywhere(name_of_check,sanitized_name,"The name that the database has for the hooked function has to appear in the dictionary");
				}
			}
		}
		else
		{
			expect_not_in_the_code(name_of_check,"dict_from_current_addresses_to_function_names","The option was off, so no dictionary of the names has to be declared");
		}
	}

	protected void check_the_option_of_the_dictionary_of_the_attach_objects()
	{
		String name_of_check="the option of the dictionary of the objects of the interceptor";
		if (this.options.isCreateDataStructureWithInterceptorAttachObjectscheckboxchecked.booleanValue())
		{
			if (the_script_carries_a_prologue().booleanValue())
			{
				expect_in_the_code(name_of_check,"var dict_with_objects_returned_from_attach","The dictionary has to be declared");
			}
			/*
			 * Only a hook that attaches has an object to store. A script whose every hook is an Interceptor.replace() has
			 * nothing to write into the dictionary, because replace() returns nothing, so the demand is made only when there is
			 * an attach in the script at all.
			 */
			if (does_the_script_install_any_hook().booleanValue()
					&& this.analyzer.return_the_code_only_text().indexOf("Interceptor.attach(dynamic_address_of_")>=0)
			{
				expect_in_the_code(name_of_check,"dict_with_objects_returned_from_attach[","Every hook that attaches has to store what the interceptor returned");
			}
			/*
			 * Careful: only the hooks that attach store something. An Interceptor.replace() returns nothing, and the blocks
			 * that scan the memory and that hook the imported symbols attach without being a hook of an address of the
			 * program, so the count is compared against the attaches of the hooks themselves.
			 */
			if (!this.options.isHookImportsCheckBoxchecked.booleanValue())
			{
				expect_the_same_count_in_the_code(name_of_check,"dict_with_objects_returned_from_attach[","Interceptor.attach(dynamic_address_of_",
						"Every hook that attaches has to store the object that the interceptor returned for it");
			}
		}
		else
		{
			expect_not_in_the_code(name_of_check,"dict_with_objects_returned_from_attach","The option was off, so the dictionary has to be absent");
		}
	}

	protected void check_the_option_of_the_imports()
	{
		String name_of_check="the option that hooks the imported symbols";
		if (this.options.isHookImportsCheckBoxchecked.booleanValue())
		{
			expect_in_the_code(name_of_check,"new ApiResolver(","The imports are found with a resolver");
			expect_the_count_in_the_code(name_of_check,"new ApiResolver(",1,"One resolver is enough for all the imports");
			expect_in_the_code(name_of_check,".enumerateMatches(","Every import is looked for by name");
			expect_in_the_code(name_of_check,"dynamic_address_of_import_","Every import that is found gets its address");
			/*Every import is only hooked when the resolver found it*/
			expect_in_the_code(name_of_check,".length>0","The hook of an import has to be guarded by the resolver having found it");
			/*How many external functions the database has, and how many the script looked for*/
			this.report.count_one_check_that_was_run();
			int how_many_external_functions_the_database_has=return_how_many_external_functions_the_database_has();
			int how_many_the_script_looks_for=this.analyzer.return_how_many_times_in_the_code(".enumerateMatches(");
			if (how_many_external_functions_the_database_has>0 && how_many_the_script_looks_for==0)
			{
				this.report.add_error(name_of_check,"no import is looked for",
						"The database has external functions but the script looks for none of them",
						how_many_external_functions_the_database_has+" external functions in the database",0);
			}
			this.report.add_info(name_of_check,"how many imports",
					"The database has "+how_many_external_functions_the_database_has+" external functions and the script looks for "+how_many_the_script_looks_for,"");
		}
		else
		{
			expect_not_in_the_code(name_of_check,"new ApiResolver(","The option was off, so no resolver has to be created");
			expect_not_in_the_code(name_of_check,"dynamic_address_of_import_","The option was off, so no import has to be hooked");
		}
	}

	protected int return_how_many_external_functions_the_database_has()
	{
		int retval=0;
		SymbolIterator symbol_iterator=this.current_program.getSymbolTable().getExternalSymbols();
		LinkedHashSet<String> the_functions_that_were_seen=new LinkedHashSet<String>();
		while (symbol_iterator!=null && symbol_iterator.hasNext())
		{
			Symbol symbol=symbol_iterator.next();
			if (symbol.getSymbolType()==SymbolType.FUNCTION && symbol.isExternal())
			{
				if (!the_functions_that_were_seen.contains(symbol.getName(true)))
				{
					the_functions_that_were_seen.add(symbol.getName(true));
					retval++;
				}
			}
		}
		return retval;
	}

	protected void check_the_option_of_the_exports()
	{
		String name_of_check="the option that hooks the exported entry points";
		if (!this.options.isHookExportsCheckBoxchecked.booleanValue())
		{
			return;
		}
		/*The database knows the entry points, so the number of hooks cannot be smaller than the number of those that are instructions*/
		this.report.count_one_check_that_was_run();
		int how_many_entry_points_are_instructions=0;
		Listing listing=this.current_program.getListing();
		ghidra.program.model.address.AddressIterator address_iterator=this.current_program.getSymbolTable().getExternalEntryPointIterator();
		while (address_iterator!=null && address_iterator.hasNext())
		{
			Address address=address_iterator.next();
			if (listing.getInstructionAt(address)!=null)
			{
				how_many_entry_points_are_instructions++;
			}
		}
		if (how_many_entry_points_are_instructions>0 && this.how_many_hooks_the_script_installs<how_many_entry_points_are_instructions)
		{
			this.report.add_error(name_of_check,"fewer hooks than entry points",
					"The database has more exported entry points that are instructions than the script has hooks",
					how_many_entry_points_are_instructions+" entry points and "+this.how_many_hooks_the_script_installs+" hooks",0);
		}
		this.report.add_info(name_of_check,"how many entry points",
				"The database has "+how_many_entry_points_are_instructions+" exported entry points that are instructions","");
	}

	protected void check_the_option_of_the_memory_scan()
	{
		String name_of_check="the option that scans the memory for a pattern";
		if (!this.options.isMemoryScanPatternCheckBoxchecked.booleanValue())
		{
			expect_not_in_the_code(name_of_check,"Memory.scanSync","The option was off, so the memory must not be scanned");
			return;
		}

		String pattern_that_was_asked_for=this.options.MemoryScanPatternTextField.getText();
		String expected_pattern=return_the_expected_frida_pattern_for(pattern_that_was_asked_for);

		if (expected_pattern.equals(""))
		{
			/*The pattern cannot be converted, so the script has to say so and must not scan anything*/
			expect_anywhere(name_of_check,"not valid","A pattern that cannot be converted has to be reported inside the script");
			expect_not_in_the_code(name_of_check,"Memory.scanSync","A pattern that cannot be converted must not lead to a scan");
			return;
		}

		expect_in_the_code(name_of_check,"Memory.scanSync","The memory has to be scanned");
		expect_in_the_code(name_of_check,"Process.enumerateModules()","The modules have to be enumerated with the current form of the api");
		expect_not_in_the_code(name_of_check,"enumerateModulesSync","The form of the api that was deprecated must not be used");
		expect_in_the_code(name_of_check,"Process.enumerateRanges(","The memory that belongs to no module has to be scanned as well");
		expect_in_the_code(name_of_check,"new ModuleMap()","A module map is needed to tell which range belongs to a module");
		expect_in_the_code(name_of_check,"Process.platform","The comparison of the name of the module has to depend on the platform");
		expect_in_the_code(name_of_check,"let constructed_str_to_print","The message of every result has to be declared with let, otherwise every hook prints the message of the last result");
		expect_not_in_the_code(name_of_check,"var constructed_str_to_print","The message of every result must not be declared with var");
		expect_in_the_code(name_of_check,"try {","Every scan has to be wrapped, a range can stop being readable");
		/*And the pattern that the script carries has to be the one that the pattern of the user converts to*/
		expect_anywhere(name_of_check,expected_pattern,"The pattern inside the script has to be the conversion of the pattern that was asked for");
	}

	/*
	 * Works out, independently of the plugin, what the frida pattern of an incoming pattern of the instruction search is.
	 * Returns the empty string when the incoming pattern is not a valid one.
	 */
	protected String return_the_expected_frida_pattern_for(String incoming_pattern)
	{
		if (incoming_pattern==null)
		{
			return "";
		}
		String pattern=incoming_pattern.toLowerCase().replace("\n"," ").replace("\r"," ").replace("\t"," ").replaceAll(" +"," ").trim();
		if (pattern.equals(""))
		{
			return "";
		}
		String bytes_of_the_result="";
		String bytes_of_the_mask="";
		String[] parts=pattern.split(" ");
		for (int i=0;i<parts.length;i++)
		{
			String part=parts[i];
			if (part.length()==2 && is_a_hexadecimal_digit(part.charAt(0)) && is_a_hexadecimal_digit(part.charAt(1)))
			{
				bytes_of_the_result+=part+" ";
				bytes_of_the_mask+="ff ";
				continue;
			}
			if (part.length()==10 && part.charAt(0)=='[' && part.charAt(9)==']')
			{
				String bits_of_the_result="";
				String bits_of_the_mask="";
				for (int j=1;j<=8;j++)
				{
					char bit=part.charAt(j);
					if (bit=='.')
					{
						bits_of_the_result+="0";
						bits_of_the_mask+="0";
					}
					else if (bit=='0' || bit=='1')
					{
						bits_of_the_result+=bit;
						bits_of_the_mask+="1";
					}
					else
					{
						return "";
					}
				}
				bytes_of_the_result+=two_hexadecimal_digits_of(Integer.parseInt(bits_of_the_result,2))+" ";
				bytes_of_the_mask+=two_hexadecimal_digits_of(Integer.parseInt(bits_of_the_mask,2))+" ";
				continue;
			}
			return "";	//neither a byte nor a mask of bits
		}
		return (bytes_of_the_result+": "+bytes_of_the_mask).trim();
	}

	protected String two_hexadecimal_digits_of(int value)
	{
		String retval=Integer.toString(value,16);
		if (retval.length()==1)
		{
			retval="0"+retval;
		}
		return retval;
	}

	protected Boolean is_a_hexadecimal_digit(char c)
	{
		return Boolean.valueOf((c>='0' && c<='9') || (c>='a' && c<='f'));
	}

	protected void check_the_options_that_refuse_to_hook_something()
	{
		String name_of_check="the options that refuse to hook something";
		if (this.seed_address==null)
		{
			return;
		}
		Function function_at_the_seed=this.current_program.getFunctionManager().getFunctionAt(this.seed_address);
		if (function_at_the_seed==null)
		{
			return;
		}

		if (this.options.isDoNotHookThunkFunctionscheckboxchecked.booleanValue() && function_at_the_seed.isThunk())
		{
			expect_the_address_not_to_be_hooked(name_of_check,"a thunk that was refused",this.seed_address,
					"The option that refuses to hook a thunk was on and the address is the beginning of a thunk");
			expect_anywhere(name_of_check,"is a thunk function, not hooking","The script has to say why the thunk was not hooked");
		}
		if (this.options.isDoNotHookExternalFunctionscheckboxchecked.booleanValue() && function_at_the_seed.isExternal())
		{
			expect_the_address_not_to_be_hooked(name_of_check,"an external function that was refused",this.seed_address,
					"The option that refuses to hook an external function was on and the address is the beginning of one");
			expect_anywhere(name_of_check,"is an external function, not hooking","The script has to say why the external function was not hooked");
		}
		if (!this.options.isDoNotHookThunkFunctionscheckboxchecked.booleanValue() && function_at_the_seed.isThunk() && this.options.isHookThisAddressCheckBoxchecked.booleanValue())
		{
			/*The other direction: with the option off, a thunk is an ordinary function and it has to be hooked*/
			expect_the_address_to_be_hooked(name_of_check,"a thunk that was not refused",this.seed_address,
					"The option that refuses to hook a thunk was off, so the thunk has to be hooked like any other function");
		}
	}

	/*
	 * The references. The database can work out exactly which addresses each of these options has to bring in, so every one
	 * of them is looked for inside the script.
	 */
	protected void check_the_options_of_the_references()
	{
		String name_of_check="the options that follow the references";
		if (this.seed_address==null)
		{
			return;
		}
		Listing listing=this.current_program.getListing();
		Function function_containing_the_seed=listing.getFunctionContaining(this.seed_address);

		if (this.options.isReferencestoAddressCheckBoxchecked.booleanValue())
		{
			CodeUnit code_unit=listing.getCodeUnitAt(this.seed_address);
			if (code_unit!=null)
			{
				int how_many_were_expected=0;
				ReferenceIterator reference_iterator=code_unit.getReferenceIteratorTo();
				while (reference_iterator!=null && reference_iterator.hasNext() && how_many_were_expected<this.how_many_things_to_enumerate_from_the_database)
				{
					Reference reference=reference_iterator.next();
					Address address_that_refers=reference.getFromAddress();
					how_many_were_expected++;
					/*Only an address that is an instruction can be hooked, the others are reported by the plugin as comments*/
					if (listing.getInstructionAt(address_that_refers)==null)
					{
						continue;
					}
					expect_the_address_to_be_hooked(name_of_check,"an address that refers to the seed",address_that_refers,
							"The option that hooks the addresses which refer to the current address was on");
				}
				this.report.add_info(name_of_check,"how many refer to the address",
						how_many_were_expected+" addresses of the database refer to "+this.seed_address,"");
			}
		}

		if (this.options.isFunctionsReferencingAddressCheckBoxchecked.booleanValue())
		{
			/*Not the address that refers, but the function that contains it*/
			CodeUnit code_unit=listing.getCodeUnitAt(this.seed_address);
			if (code_unit!=null)
			{
				int how_many_were_checked=0;
				ReferenceIterator reference_iterator=code_unit.getReferenceIteratorTo();
				while (reference_iterator!=null && reference_iterator.hasNext() && how_many_were_checked<this.how_many_things_to_enumerate_from_the_database)
				{
					Reference reference=reference_iterator.next();
					Function function_that_contains_the_reference=listing.getFunctionContaining(reference.getFromAddress());
					if (function_that_contains_the_reference==null)
					{
						continue;
					}
					how_many_were_checked++;
					if (listing.getInstructionAt(function_that_contains_the_reference.getEntryPoint())==null)
					{
						continue;
					}
					expect_the_address_to_be_hooked(name_of_check,"a function that contains a reference to the seed",function_that_contains_the_reference.getEntryPoint(),
							"The option that hooks the functions which contain code referring to the current address was on");
				}
			}
		}

		if (this.options.isReferencestoFunctionCheckboxchecked.booleanValue() && function_containing_the_seed!=null)
		{
			/*The addresses that refer to the beginning of the function that contains the seed*/
			Instruction instruction_at_the_beginning=listing.getInstructionAt(function_containing_the_seed.getEntryPoint());
			if (instruction_at_the_beginning!=null)
			{
				int how_many_were_checked=0;
				ReferenceIterator reference_iterator=instruction_at_the_beginning.getReferenceIteratorTo();
				while (reference_iterator!=null && reference_iterator.hasNext() && how_many_were_checked<this.how_many_things_to_enumerate_from_the_database)
				{
					Reference reference=reference_iterator.next();
					how_many_were_checked++;
					Address address_that_refers=reference.getFromAddress();
					if (listing.getInstructionAt(address_that_refers)==null)
					{
						continue;
					}
					expect_the_address_to_be_hooked(name_of_check,"an address that refers to the function of the seed",address_that_refers,
							"The option that hooks the addresses which refer to the current function was on");
				}
			}
		}

		if (this.options.isOutReferencesfromAddressCheckBoxchecked.booleanValue())
		{
			/*The other direction: the addresses that the seed itself refers to*/
			CodeUnit code_unit=listing.getCodeUnitAt(this.seed_address);
			if (code_unit!=null)
			{
				Reference[] the_references_that_go_out=code_unit.getReferencesFrom();
				for (int i=0;i<the_references_that_go_out.length && i<this.how_many_things_to_enumerate_from_the_database;i++)
				{
					Address address_that_is_referred=the_references_that_go_out[i].getToAddress();
					if (listing.getInstructionAt(address_that_is_referred)==null)
					{
						continue;
					}
					expect_the_address_to_be_hooked(name_of_check,"an address that the seed refers to",address_that_is_referred,
							"The option that hooks the addresses referred to by the current address was on");
				}
			}
		}

		if (this.options.isFunctionsReferencingFunctionCheckboxchecked.booleanValue() && function_containing_the_seed!=null)
		{
			/*Every function that calls this one, for the first level of depth, has to be hooked*/
			Set<Function> the_functions_that_call_it=function_containing_the_seed.getCallingFunctions(null);
			if (the_functions_that_call_it!=null)
			{
				int how_many_were_checked=0;
				for (Function function_that_calls: the_functions_that_call_it)
				{
					if (how_many_were_checked>=this.how_many_things_to_enumerate_from_the_database)
					{
						break;
					}
					how_many_were_checked++;
					if (listing.getInstructionAt(function_that_calls.getEntryPoint())==null)
					{
						continue;
					}
					expect_the_address_to_be_hooked(name_of_check,"a function that calls the seed",function_that_calls.getEntryPoint(),
							"The option that hooks the functions which call the current one was on");
				}
				this.report.add_info(name_of_check,"how many call the function",
						the_functions_that_call_it.size()+" functions of the database call "+function_containing_the_seed.getName(),"");
			}
		}

		if (this.options.isOutReferencesfromFunctionCheckBoxchecked.booleanValue() && function_containing_the_seed!=null)
		{
			Set<Function> the_functions_that_it_calls=function_containing_the_seed.getCalledFunctions(null);
			if (the_functions_that_it_calls!=null)
			{
				int how_many_were_checked=0;
				for (Function function_that_is_called: the_functions_that_it_calls)
				{
					if (how_many_were_checked>=this.how_many_things_to_enumerate_from_the_database)
					{
						break;
					}
					how_many_were_checked++;
					if (listing.getInstructionAt(function_that_is_called.getEntryPoint())==null)
					{
						continue;
					}
					expect_the_address_to_be_hooked(name_of_check,"a function that the seed calls",function_that_is_called.getEntryPoint(),
							"The option that hooks the functions which the current one calls was on");
				}
				this.report.add_info(name_of_check,"how many the function calls",
						the_functions_that_it_calls.size()+" functions are called by "+function_containing_the_seed.getName(),"");
			}
		}
	}

	/*
	 * The ranges. The database can count the functions and the instructions that follow an address, so the number of the
	 * hooks can be compared with the number that was asked for.
	 */
	protected void check_the_options_of_the_ranges()
	{
		String name_of_check="the options that hook a range";
		if (this.seed_address==null)
		{
			return;
		}

		if (this.options.isRangeFunctionsCheckBoxchecked.booleanValue() && this.options.RangeFunctionsNum>0 && this.options.RangeFunctionsRadioButtonFun.isSelected())
		{
			/*The functions that follow the address, the one that contains it counting as the first*/
			ArrayList<Address> the_functions_that_were_expected=new ArrayList<Address>();
			Function function_containing=this.current_program.getListing().getFunctionContaining(this.seed_address);
			if (function_containing!=null)
			{
				the_functions_that_were_expected.add(function_containing.getEntryPoint());
			}
			FunctionIterator function_iterator=this.current_program.getListing().getFunctions(this.seed_address,true);
			while (function_iterator!=null && function_iterator.hasNext() && the_functions_that_were_expected.size()<this.options.RangeFunctionsNum)
			{
				Function function=function_iterator.next();
				if (function_containing!=null && function.getEntryPoint().equals(function_containing.getEntryPoint()))
				{
					continue;
				}
				the_functions_that_were_expected.add(function.getEntryPoint());
			}
			for (int i=0;i<the_functions_that_were_expected.size();i++)
			{
				Address address=the_functions_that_were_expected.get(i);
				if (would_an_option_refuse_to_hook(address).booleanValue())
				{
					continue;	//collected by the range and then declined by one of the options that refuse, which is right
				}
				expect_the_address_to_be_hooked(name_of_check,"a function of the range",address,
						"A range of "+this.options.RangeFunctionsNum+" functions was asked for, starting from "+this.seed_address);
			}
			this.report.add_info(name_of_check,"the range of functions",
					"A range of "+this.options.RangeFunctionsNum+" functions was asked for and "+the_functions_that_were_expected.size()+" were found in the database","");
		}

		if (this.options.isRangeAddressesCheckBoxchecked.booleanValue() && this.options.RangeAddressesNum>0 && this.options.RangeAddressesRadioButtonInstr.isSelected())
		{
			/*The instructions that follow the address. The plugin counts the one at the address as the first*/
			int how_many_were_expected=0;
			ghidra.program.model.listing.InstructionIterator instruction_iterator=this.current_program.getListing().getInstructions(this.seed_address,true);
			while (instruction_iterator!=null && instruction_iterator.hasNext() && how_many_were_expected<this.options.RangeAddressesNum)
			{
				Instruction instruction=instruction_iterator.next();
				how_many_were_expected++;
				expect_the_address_to_be_hooked(name_of_check,"an instruction of the range",instruction.getAddress(),
						"A range of "+this.options.RangeAddressesNum+" instructions was asked for, starting from "+this.seed_address);
			}
			this.report.add_info(name_of_check,"the range of instructions",
					"A range of "+this.options.RangeAddressesNum+" instructions was asked for and "+how_many_were_expected+" were found in the database","");
		}
	}

	/*The options that report where a computed call is going to land*/
	protected void check_the_options_of_the_computed_calls()
	{
		String name_of_check="the options that report the destination of a computed call";
		Boolean one_of_the_two_options_is_on=Boolean.valueOf(this.options.isOutDynamicCallReferencesfromAddressCheckBoxchecked.booleanValue()
				|| this.options.isOutDynamicCallReferencesfromFunctionCheckBoxchecked.booleanValue());

		if (!one_of_the_two_options_is_on.booleanValue())
		{
			expect_not_in_the_code(name_of_check,"calculated_target_address_for_initial_address_","No option about the computed calls was on, so no destination has to be calculated");
			expect_not_in_the_code(name_of_check,"var modulemap_for_all_modules","No option about the computed calls was on, so no module map is needed");
			return;
		}

		/*The module map is created once, before the hooks, and never inside one*/
		expect_in_the_code(name_of_check,"var modulemap_for_all_modules","A module map is needed to find the module that the destination belongs to");
		expect_the_count_in_the_code(name_of_check,"var modulemap_for_all_modules",1,"The module map has to be created once, and not again inside every hook");

		/*
		 * Careful: x86:LE: and not x86:LE:64 . Both widths of x86 have a parser of the computed calls, and while this said 64 the
		 * whole block below returned early for a 32 bit program, so everything it demands about the destination of a computed call
		 * was never actually asked of one.
		 */
		String language_of_the_program=this.current_program.getLanguage().getLanguageID().toString();
		Boolean the_architecture_is_supported=Boolean.valueOf(language_of_the_program.indexOf("x86:LE:")>=0
				|| language_of_the_program.indexOf("AARCH64:LE:64")>=0 || language_of_the_program.indexOf("ARM:LE:32")>=0);
		if (!the_architecture_is_supported.booleanValue())
		{
			return;
		}

		/*
		 * When the seed really is a computed call, the script has to say something about its destination: either the code that
		 * calculates it, or a comment that says why it could not.
		 *
		 * Careful: the second half of that is not a loophole, it is the case of a hook that was asked to have no onEnter. The code
		 * that calculates the destination reads the registers at the entry of the function, so the onEnter is the only place it
		 * could be written into, and a hook without one cannot carry it. The plugin writes a comment saying exactly that, which is
		 * what this check accepts, so an option that was switched on never looks as if it had merely been ignored.
		 */
		if (this.seed_address!=null)
		{
			/*
			 * Careful: a computed flow whose destination cannot be worked out, such as the UD2 of x86, is not something the plugin
			 * undertakes to report, so nothing is demanded of it. The one criterion lives in SelfTestRunner and both the choosing
			 * of the addresses and this check ask it, so the two cannot disagree about what a computed call is.
			 */
			Instruction instruction_at_the_seed=this.current_program.getListing().getInstructionAt(this.seed_address);
			/*
			 * Careful: and the address has to have been hooked at all. A thunk of an imported function is a computed jump through
			 * the table of the imports, so its destination is one the plugin can report, but when the option that refuses to hook
			 * the thunks is on there is no hook for it to be reported in. The script says that it is not hooking it, which is the
			 * whole of what it has to say.
			 */
			if (SelfTestRunner.can_the_destination_of_this_instruction_be_reported(instruction_at_the_seed,language_of_the_program).booleanValue()
					&& !was_the_seed_address_refused_on_purpose().booleanValue())
			{
				this.report.count_one_check_that_was_run();
				Boolean the_destination_is_calculated=Boolean.valueOf(this.analyzer.return_how_many_times_in_the_code("calculated_target_address_for_initial_address_")>0);
				Boolean there_is_a_comment_that_explains=Boolean.valueOf(this.analyzer.return_the_positions_anywhere_of("The destination of the computed").size()>0);
				if (!the_destination_is_calculated.booleanValue() && !there_is_a_comment_that_explains.booleanValue())
				{
					this.report.add_error(name_of_check,"nothing is said about a computed call",
							"The hooked address is a computed call and one of the options that report its destination was on, but the script neither calculates the destination nor says why it could not",
							"the instruction at "+this.seed_address+" is '"+instruction_at_the_seed.toString()+"'",0);
				}
				/*When the destination is calculated, the module map has to be consulted and the result has to be printed*/
				if (the_destination_is_calculated.booleanValue())
				{
					expect_in_the_code(name_of_check,"modulemap_for_all_modules.find(","The module that the destination belongs to has to be looked for");
					expect_in_the_code(name_of_check,"modulemap_for_all_modules.update()","The module map has to be refreshed when a destination is not found, a module can be loaded later");
					expect_anywhere(name_of_check,"Next destination","The destination has to be printed");
					expect_in_the_code(name_of_check,"DebugSymbol.fromAddress","The debug information of the destination has to be printed");
				}
			}
		}
	}
}
