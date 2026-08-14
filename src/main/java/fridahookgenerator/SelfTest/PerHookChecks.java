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
import java.util.LinkedHashMap;

import fridahookgenerator.AdvancedHookOptionsDialog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

/*
 * Looks at every hook of the generated script on its own.
 *
 * The checks that came before this one look at the whole script and count things. That finds a great deal, but it cannot
 * see that one particular hook is missing half of itself, because the totals still add up. So this class cuts the script
 * into the hooks that it is made of, works out which of the three forms each one was written in, and then asks of each
 * hook the questions that only make sense for one hook: does it declare its own offset, does it use the very identifier
 * that it declared, does it announce the name that the database has for the function it sits on, does it print more
 * arguments than that function has, does the signature of the replacement agree with itself.
 *
 * The three forms that the plugin writes are:
 *   - a function hook, which attaches an object with an onEnter() and an onLeave()
 *   - an address hook, which attaches a standalone function that is called when the code reaches the address
 *   - a replacement, which replaces the function with a NativeCallback and calls the original through a NativeFunction
 */
public class PerHookChecks {

	protected Program current_program;
	protected SelfTestReport report;
	protected AdvancedHookOptionsDialog options;
	protected JavascriptTextAnalyzer analyzer;
	protected int how_many_hooks_to_examine;
	protected String characters_allowed_in_variable_name="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";

	public PerHookChecks(Program current_program,SelfTestReport report,AdvancedHookOptionsDialog options,JavascriptTextAnalyzer analyzer,int how_many_hooks_to_examine)
	{
		this.current_program=current_program;
		this.report=report;
		this.options=options;
		this.analyzer=analyzer;
		this.how_many_hooks_to_examine=how_many_hooks_to_examine;
	}

	/*One hook of the generated script, cut out of it*/
	public class OneHook
	{
		public String identifier="";		//what follows "offset_of_" , which every name of this hook is built from
		public String hexadecimal_of_the_offset="";
		public Boolean the_offset_is_subtracted=false;
		public int position_where_it_starts=0;
		public int line_where_it_starts=0;
		public String text="";			//the whole text of the hook, comments and strings included
		public String form="unknown";		//"function hook", "address hook", "replacement" or "unknown"
		public Address address=null;		//worked out from the offset and the image base, null when it cannot be
		/*
		 * Careful: a hook carries comments, and one of them is a commented out Interceptor.attach() that shows the user how
		 * to hook the destination of a computed call. Anything that counts constructs of the language therefore has to count
		 * them in this, where the comments and the strings have been blanked out, and not in the text itself.
		 */
		public JavascriptTextAnalyzer analyzer_of_the_hook=null;
	}

	public void run_all_the_checks_on_every_hook()
	{
		ArrayList<OneHook> the_hooks=cut_the_script_into_hooks();
		LinkedHashSet<String> identifiers_that_were_seen=new LinkedHashSet<String>();

		this.report.add_info("the hooks of the script","how many",
				"The script is made of "+the_hooks.size()+" hooks, of which "+Math.min(the_hooks.size(),this.how_many_hooks_to_examine)+" were examined one by one","");

		check_that_no_two_hooks_share_a_name_or_an_address(the_hooks);
		check_that_nothing_comes_after_the_flush(the_hooks);

		int how_many_were_examined=0;
		for (int i=0;i<the_hooks.size() && how_many_were_examined<this.how_many_hooks_to_examine;i++)
		{
			OneHook hook=the_hooks.get(i);
			how_many_were_examined++;
			/*
			 * Two hooks for the same address means that two of the ways of collecting the addresses arrived at it and the
			 * plugin failed to notice. The script would then install the same hook twice, print everything twice, and the
			 * reasons of the second one would be missing from the first.
			 */
			if (identifiers_that_were_seen.contains(hook.identifier))
			{
				this.report.count_one_check_that_was_run();
				this.report.add_error("the identifiers of the hooks","the same address is hooked twice",
						"Two hooks of the script were written for the same address, so it is hooked twice",
						"the identifier '"+hook.identifier+"' is used by more than one hook",hook.line_where_it_starts);
			}
			identifiers_that_were_seen.add(hook.identifier);
			check_the_things_that_every_hook_has(hook);
			check_the_backtrace_of_the_hook(hook);
			check_the_options_that_write_inside_the_hook(hook);
			check_the_two_variables_that_open_the_hook(hook);
			if (hook.form.equals("function hook"))
			{
				check_a_function_hook(hook);
			}
			else if (hook.form.equals("address hook"))
			{
				check_an_address_hook(hook);
			}
			else if (hook.form.equals("replacement"))
			{
				check_a_replacement(hook);
			}
			else
			{
				this.report.add_error("the form of a hook","unknown form",
						"A hook was generated in none of the three forms that the plugin writes",
						"the hook of '"+hook.identifier+"' declares an offset but attaches nothing",hook.line_where_it_starts);
			}
			check_a_hook_against_the_database(hook);
		}
	}

	/*================================================================================================================
	 * cutting the script into its hooks
	 *==============================================================================================================*/

	/*
	 * Every hook begins with the declaration of its own offset, and it ends where the next one begins. Careful: the block
	 * that scans the memory for a pattern and the block that hooks the imported symbols declare no offset and are written
	 * before the hooks, so they are outside of every hook and are not cut into one.
	 */
	protected ArrayList<OneHook> cut_the_script_into_hooks()
	{
		ArrayList<OneHook> retval=new ArrayList<OneHook>();
		String code=this.analyzer.return_the_code_only_text();
		String whole_text=this.analyzer.return_the_original_text();
		ArrayList<Integer> positions=this.analyzer.return_the_positions_in_the_code_of("var offset_of_");

		/*Where the hooks stop: the flush of the interceptors belongs to the epilogue and is not part of the last hook*/
		int position_where_the_hooks_end=code.indexOf("Interceptor.flush()");
		if (position_where_the_hooks_end<0)
		{
			position_where_the_hooks_end=whole_text.length();
		}

		for (int i=0;i<positions.size();i++)
		{
			int position=positions.get(i).intValue();
			int end_of_this_hook=position_where_the_hooks_end;
			if (i+1<positions.size() && positions.get(i+1).intValue()<end_of_this_hook)
			{
				end_of_this_hook=positions.get(i+1).intValue();
			}
			if (end_of_this_hook<position)
			{
				end_of_this_hook=whole_text.length();
			}

			OneHook hook=new OneHook();
			hook.position_where_it_starts=position;
			hook.line_where_it_starts=this.analyzer.return_the_line_number_of_the_position(position);
			hook.text=whole_text.substring(position,end_of_this_hook);

			/*The identifier is what follows "offset_of_" , and every other name of the hook is built out of it*/
			int position_of_the_identifier=position+"var offset_of_".length();
			int j=position_of_the_identifier;
			while (j<code.length() && JavascriptTextAnalyzer.is_a_character_that_can_be_inside_a_name(code.charAt(j)).booleanValue())
			{
				j++;
			}
			hook.identifier=code.substring(position_of_the_identifier,j);

			/*And the value of the offset, with the operation that is applied on the base of the module giving its sign*/
			int position_of_the_0x=code.indexOf("0x",j);
			if (position_of_the_0x>=0 && position_of_the_0x<end_of_this_hook)
			{
				int k=position_of_the_0x+2;
				int start_of_the_digits=k;
				while (k<code.length() && is_a_hexadecimal_digit(code.charAt(k)).booleanValue())
				{
					k++;
				}
				hook.hexadecimal_of_the_offset=code.substring(start_of_the_digits,k);
			}
			if (hook.text.indexOf(".sub(offset_of_"+hook.identifier+")")>=0)
			{
				hook.the_offset_is_subtracted=true;
			}
			hook.address=work_out_the_address_of(hook);
			hook.analyzer_of_the_hook=new JavascriptTextAnalyzer(hook.text);
			hook.form=work_out_the_form_of(hook);

			retval.add(hook);
		}
		return retval;
	}

	protected Address work_out_the_address_of(OneHook hook)
	{
		if (hook.hexadecimal_of_the_offset.equals(""))
		{
			return null;
		}
		try {
			long value=Long.parseLong(hook.hexadecimal_of_the_offset,16);
			if (hook.the_offset_is_subtracted.booleanValue())
			{
				return this.current_program.getImageBase().subtract(value);
			}
			return this.current_program.getImageBase().add(value);
		}
		catch (Exception ex)
		{
			return null;
		}
	}

	protected String work_out_the_form_of(OneHook hook)
	{
		String code=hook.analyzer_of_the_hook.return_the_code_only_text();
		if (code.indexOf("Interceptor.replace(")>=0)
		{
			return "replacement";
		}
		if (code.indexOf("onEnter:")>=0 || code.indexOf("onLeave:")>=0)
		{
			return "function hook";
		}
		if (code.indexOf("function function_to_call_when_code_reaches_")>=0)
		{
			return "address hook";
		}
		return "unknown";
	}

	/*================================================================================================================
	 * the helpers that report about one hook
	 *==============================================================================================================*/

	/*
	 * The signature of a finding must not carry the name of one hook, otherwise the same problem on a thousand hooks is
	 * reported as a thousand different problems. The name of the hook is taken out of it and replaced by a placeholder.
	 */
	protected String return_a_generic_signature(OneHook hook,String needle)
	{
		if (hook.identifier.equals(""))
		{
			return needle;
		}
		return needle.replace(hook.identifier,"<the name of the hook>");
	}

	/*Looks at the code of the hook: the comments and the strings have been blanked out*/
	protected void expect_in_the_hook_code(String name_of_check,OneHook hook,String needle,String why)
	{
		this.report.count_one_check_that_was_run();
		if (hook.analyzer_of_the_hook.return_the_code_only_text().indexOf(needle)<0)
		{
			this.report.add_error(name_of_check,"missing "+return_a_generic_signature(hook,needle),why,"",hook.line_where_it_starts)
					.with("the code of the hook contains \""+needle+"\"","yes","no, it is nowhere in the hook")
					.at("the hook of '"+hook.identifier+"'")
					.with_the_context("the hook, as it was generated",hook.text);
		}
	}

	protected void expect_not_in_the_hook_code(String name_of_check,OneHook hook,String needle,String why)
	{
		this.report.count_one_check_that_was_run();
		String code=hook.analyzer_of_the_hook.return_the_code_only_text();
		if (code.indexOf(needle)>=0)
		{
			this.report.add_error(name_of_check,"unexpected "+return_a_generic_signature(hook,needle),why,"",hook.line_where_it_starts)
					.with("the code of the hook contains \""+needle+"\"","no","yes, "+return_how_many_times_in(code,needle)+" times")
					.at("the hook of '"+hook.identifier+"'")
					.with_the_context("the hook, as it was generated",hook.text);
		}
	}

	/*Looks at the whole text of the hook, comments and strings included, which is where the messages that it prints live*/
	protected void expect_in_the_hook(String name_of_check,OneHook hook,String needle,String why)
	{
		this.report.count_one_check_that_was_run();
		if (hook.text.indexOf(needle)<0)
		{
			this.report.add_error(name_of_check,"missing "+return_a_generic_signature(hook,needle),why,"",hook.line_where_it_starts)
					.with("the hook contains \""+needle+"\"","yes","no, it is nowhere in the hook")
					.at("the hook of '"+hook.identifier+"'")
					.with_the_context("the hook, as it was generated",hook.text);
		}
	}

	protected void expect_not_in_the_hook(String name_of_check,OneHook hook,String needle,String why)
	{
		this.report.count_one_check_that_was_run();
		if (hook.text.indexOf(needle)>=0)
		{
			this.report.add_error(name_of_check,"unexpected "+return_a_generic_signature(hook,needle),why,"",hook.line_where_it_starts)
					.with("the hook contains \""+needle+"\"","no","yes, "+return_how_many_times_in(hook.text,needle)+" times")
					.at("the hook of '"+hook.identifier+"'")
					.with_the_context("the hook, as it was generated",hook.text);
		}
	}

	protected void expect_the_count_in_the_hook(String name_of_check,OneHook hook,String needle,int how_many_were_expected,String why)
	{
		this.report.count_one_check_that_was_run();
		int how_many_there_are=return_how_many_times_in(hook.analyzer_of_the_hook.return_the_code_only_text(),needle);
		if (how_many_there_are!=how_many_were_expected)
		{
			this.report.add_error(name_of_check,"count of "+return_a_generic_signature(hook,needle),why,"",hook.line_where_it_starts)
					.with("how many times the code of the hook contains \""+needle+"\"",""+how_many_were_expected,""+how_many_there_are)
					.at("the hook of '"+hook.identifier+"'")
					.with_the_context("the hook, as it was generated",hook.text);
		}
	}

	protected void expect_the_first_before_the_second(String name_of_check,OneHook hook,String first_needle,String second_needle,String why)
	{
		this.report.count_one_check_that_was_run();
		int position_of_the_first=hook.text.indexOf(first_needle);
		int position_of_the_second=hook.text.indexOf(second_needle);
		if (position_of_the_first<0 || position_of_the_second<0)
		{
			return;	//one of the two is not there at all, which the checks that look for them report on their own
		}
		if (position_of_the_first>position_of_the_second)
		{
			this.report.add_error(name_of_check,first_needle+" after "+second_needle,why,
					"the hook of '"+hook.identifier+"' has '"+first_needle+"' after '"+second_needle+"'",hook.line_where_it_starts);
		}
	}

	protected int return_how_many_times_in(String text,String needle)
	{
		int retval=0;
		int position=text.indexOf(needle);
		while (position>=0)
		{
			retval++;
			position=text.indexOf(needle,position+1);
		}
		return retval;
	}

	protected Boolean is_a_hexadecimal_digit(char c)
	{
		return Boolean.valueOf((c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F'));
	}

	/*================================================================================================================
	 * what every hook has to have, whatever its form
	 *==============================================================================================================*/

	protected void check_the_things_that_every_hook_has(OneHook hook)
	{
		String name_of_check="the structure of one hook";

		/*The identifier has to be a name that javascript accepts, and it has to be there at all*/
		this.report.count_one_check_that_was_run();
		if (hook.identifier.equals(""))
		{
			this.report.add_error(name_of_check,"a hook without a name","A hook declares an offset whose name is empty","",hook.line_where_it_starts);
			return;
		}
		this.report.count_one_check_that_was_run();
		if (!JavascriptTextAnalyzer.is_a_plain_javascript_name("offset_of_"+hook.identifier).booleanValue())
		{
			this.report.add_error(name_of_check,"a name that javascript will not accept",
					"The name that a hook builds its variables from is not a name that javascript accepts",
					"the identifier is '"+hook.identifier+"'",hook.line_where_it_starts);
		}

		/*An offset has to have been computed, and it has to be a hexadecimal number*/
		this.report.count_one_check_that_was_run();
		if (hook.hexadecimal_of_the_offset.equals(""))
		{
			this.report.add_error(name_of_check,"a hook without an offset",
					"A hook declares an offset with no hexadecimal value after it","the hook of '"+hook.identifier+"'",hook.line_where_it_starts);
		}

		/*The address of the module is computed out of the offset, and the two names have to agree*/
		expect_in_the_hook_code(name_of_check,hook,"var dynamic_address_of_"+hook.identifier,
				"Every hook computes the address inside the loaded module out of its offset");
		expect_in_the_hook_code(name_of_check,hook,"offset_of_"+hook.identifier+")",
				"The address of a hook has to be computed from the offset that the very same hook declared");
		expect_in_the_hook_code(name_of_check,hook,"Process.getModuleByName(",
				"Every hook resolves the module on its own, so that it can be copied out and pasted on its own");

		/*The offset is declared once and used once, and the dynamic address is declared once and used at least once*/
		expect_the_count_in_the_hook(name_of_check,hook,"var offset_of_"+hook.identifier+"=",1,"The offset of a hook is declared exactly once");
		expect_the_count_in_the_hook(name_of_check,hook,"var dynamic_address_of_"+hook.identifier+"=",1,"The address of a hook is declared exactly once");
		this.report.count_one_check_that_was_run();
		if (return_how_many_times_in(hook.text,"dynamic_address_of_"+hook.identifier)<2)
		{
			this.report.add_error(name_of_check,"an address that is declared and never used",
					"A hook computes the address inside the module and then never uses it, so nothing is hooked",
					"the hook of '"+hook.identifier+"'",hook.line_where_it_starts);
		}

		/*Exactly one call of the interceptor per hook*/
		this.report.count_one_check_that_was_run();
		/*
		 * Careful: the code of the hook, not its text. The block of a computed call carries a commented out
		 * Interceptor.attach() on the target of the call, as a suggestion to the user, and counting the text reports every
		 * one of those hooks as having installed itself twice.
		 */
		String code_of_the_hook=hook.analyzer_of_the_hook.return_the_code_only_text();
		int how_many_calls_of_the_interceptor=return_how_many_times_in(code_of_the_hook,"Interceptor.attach(")+return_how_many_times_in(code_of_the_hook,"Interceptor.replace(");
		if (how_many_calls_of_the_interceptor!=1)
		{
			this.report.add_error(name_of_check,"the number of the calls of the interceptor",
					"A hook has to call the interceptor exactly once, this one calls it "+how_many_calls_of_the_interceptor+" times",
					"the hook of '"+hook.identifier+"'",hook.line_where_it_starts);
		}

		/*The braces of one hook close inside that hook*/
		check_that_the_brackets_of_the_hook_are_balanced(hook);

		/*The marker of the code that is added later must never survive inside a hook*/
		expect_not_in_the_hook(name_of_check,hook,"PLACEHOLDER","No marker of the generator may be left inside a hook");

		/*A hook always announces itself, otherwise there is no point in it*/
		expect_in_the_hook_code(name_of_check,hook,"console.log(","A hook that prints nothing tells the user nothing");
	}

	protected void check_that_the_brackets_of_the_hook_are_balanced(OneHook hook)
	{
		String name_of_check="the structure of one hook";
		JavascriptTextAnalyzer analyzer_of_the_hook=new JavascriptTextAnalyzer(hook.text);
		char[][] pairs={{'{','}'},{'(',')'},{'[',']'}};
		for (int i=0;i<pairs.length;i++)
		{
			this.report.count_one_check_that_was_run();
			int balance=analyzer_of_the_hook.return_the_balance_of(pairs[i][0],pairs[i][1]);
			if (balance!=0)
			{
				this.report.add_error(name_of_check,"the brackets of a hook "+pairs[i][0],
						"The brackets of one hook do not close inside that hook, so the hooks that follow it are inside it",
						"the hook of '"+hook.identifier+"' is off by "+balance+" for '"+pairs[i][0]+"'",hook.line_where_it_starts);
			}
		}
	}

	/*================================================================================================================
	 * a function hook: the form with an onEnter() and an onLeave()
	 *==============================================================================================================*/

	/*
	 * The backtrace of one hook.
	 *
	 * There is more to check here than whether the line is present, and the interesting part is the first argument that is
	 * handed to Thread.backtrace(). Passing null does not mean "no context available" to frida, it means "unwind from
	 * wherever the javascript happens to be", which is inside frida's own trampoline: the accurate backtracer cannot cross
	 * it and stops early, so the caller that the user is looking for is missing from the result. Every hook that this plugin
	 * writes has the context of the hooked thread in its "this", so null is never the right thing to write.
	 *
	 * The other part is where the line is allowed to be missing, which is not the same question:
	 *   - the first two ways of the combo box only ask for a backtrace where a function begins, so an address hook in the
	 *     middle of a function is right to carry none,
	 *   - the backtrace of a function hook is written inside its onEnter, so a hook that was asked to have no onEnter is
	 *     right to carry none either,
	 *   - a replacement is entered at the beginning of the function it replaces, so it is a function beginning and every one
	 *     of the four ways has to put a backtrace in it.
	 *
	 * One consequence of the above is intended and must not be "fixed": when the user asks for the beginnings of the functions
	 * to be hooked as ordinary addresses, those hooks carry no backtrace under the first two ways, because they are ordinary
	 * address hooks and the code that writes the backtrace treats them as such. The option that turns a function beginning into
	 * an ordinary address is meant to take everything that being a function brings with it, the backtrace included.
	 */
	protected void check_the_backtrace_of_the_hook(OneHook hook)
	{
		String name_of_check="the backtrace of one hook";
		String code_of_the_hook=hook.analyzer_of_the_hook.return_the_code_only_text();

		/*Never null, in any hook, whatever the options were. This one does not depend on the option being on at all*/
		expect_not_in_the_hook_code(name_of_check,hook,"Thread.backtrace(null",
				"The context of the hooked thread has to be handed to the backtracer, or it unwinds from frida's own frames instead of from the hooked place");

		if (!this.options.isGenerateBacktraceCheckboxchecked.booleanValue())
		{
			expect_not_in_the_hook_code(name_of_check,hook,"Thread.backtrace","The option was off, so this hook must not ask for a backtrace");
			return;
		}

		int index_of_the_way=this.options.GenerateBacktracecomboBox.getSelectedIndex();
		Boolean the_way_covers_every_hook=Boolean.valueOf(index_of_the_way==2 || index_of_the_way==3);
		Boolean the_onEnter_was_asked_to_be_absent=Boolean.valueOf(this.options.isCustomFunInterceptorHookOutputCheckboxchecked.booleanValue()
				&& this.options.CustomFunInterceptorHookOutputcomboBox.getSelectedIndex()==0);

		Boolean this_hook_has_to_carry_a_backtrace=Boolean.valueOf(false);
		if (hook.form.equals("replacement"))
		{
			this_hook_has_to_carry_a_backtrace=Boolean.valueOf(true);
		}
		else if (hook.form.equals("function hook"))
		{
			this_hook_has_to_carry_a_backtrace=Boolean.valueOf(!the_onEnter_was_asked_to_be_absent.booleanValue());
		}
		else if (hook.form.equals("address hook"))
		{
			this_hook_has_to_carry_a_backtrace=the_way_covers_every_hook;
		}

		if (this_hook_has_to_carry_a_backtrace.booleanValue())
		{
			expect_in_the_hook_code(name_of_check,hook,"Thread.backtrace(this.context",
					"This hook is one of the ones that the chosen way of the backtrace covers, so it has to ask for one, with the context of the thread");
		}
		if (!the_way_covers_every_hook.booleanValue() && hook.form.equals("address hook"))
		{
			expect_not_in_the_hook_code(name_of_check,hook,"Thread.backtrace",
					"The backtrace was asked for only where a function begins, and this hook is an address in the middle of one");
		}

		if (code_of_the_hook.indexOf("Thread.backtrace")<0)
		{
			return;	//nothing else to say about a line that is not there, and whether that is right was decided above
		}

		/*The accurate and the fuzzy backtracer are the two halves of the combo box, and only one of them can be in the hook*/
		if (index_of_the_way==0 || index_of_the_way==2)
		{
			expect_in_the_hook_code(name_of_check,hook,"Backtracer.ACCURATE","The accurate backtracer was the one that was asked for");
		}
		else
		{
			expect_in_the_hook_code(name_of_check,hook,"Backtracer.FUZZY","The fuzzy backtracer was the one that was asked for");
		}
		expect_in_the_hook_code(name_of_check,hook,"DebugSymbol.fromAddress","The addresses of the backtrace have to be turned into names");
		expect_the_count_in_the_hook(name_of_check,hook,"Thread.backtrace(",1,"One hook asks for one backtrace");

		/*
		 * The line of the backtrace has to be indented like the line that announces the hook, because the two are written
		 * into the same block. They stopped agreeing when the code that writes the backtrace was told the wrong thing about
		 * the block: the depth of the indentation used to be decided by the same flag that decided whether the hook is at the
		 * beginning of a function, and inside an Interceptor.replace() those two are not the same answer.
		 */
		String indentation_of_the_backtrace=return_the_indentation_of_the_line_that_contains(hook,"Thread.backtrace(");
		String indentation_of_the_announcement=return_the_indentation_of_the_line_that_contains(hook,hook.form.equals("replacement")?"\"Entered ":"console.log(");
		this.report.count_one_check_that_was_run();
		if (indentation_of_the_backtrace!=null && indentation_of_the_announcement!=null
				&& !indentation_of_the_backtrace.equals(indentation_of_the_announcement))
		{
			this.report.add_error(name_of_check,"the indentation of the line of the backtrace",
					"The line of the backtrace is not indented like the line that announces the hook, although both are written into the same block",
					"the backtrace is indented by "+indentation_of_the_backtrace.length()+" characters and the announcement by "
					+indentation_of_the_announcement.length()+", in the hook of '"+hook.identifier+"'",hook.line_where_it_starts)
				.with_the_context("the hook of "+hook.identifier,hook.text);
		}

		/*
		 * Inside a replacement the backtrace has to be taken before the original function is called. The context that is
		 * handed over is a snapshot of the registers at the entry, so the result would not change, but a backtrace that is
		 * printed after the original ran is in the wrong place in the log and reads as if it belonged to the return.
		 */
		if (hook.form.equals("replacement"))
		{
			expect_the_first_before_the_second(name_of_check,hook,"Thread.backtrace(","var retval=NativeFunction_of_"+hook.identifier,
					"The backtrace of a replacement belongs before the call of the original function");
		}
	}

	/*
	 * The options that write something inside a hook, checked against the form of this particular hook.
	 *
	 * This is where the crossing of the options is decided, because an option on its own cannot say whether its code has to be
	 * in a given hook. The reasons and the text that goes first are written into the onEnter, the text that goes last into the
	 * onLeave, and a replacement has neither of the two halves but is entered at the beginning of the function, so it carries
	 * both. Only the form of the hook in front of us can settle it.
	 */
	/*
	 * The two variables that open every hook have to be the same name, and the second has to be built out of the first.
	 * The plugin writes "var offset_of_X=...;" and then "var dynamic_address_of_X=...base.add(offset_of_X);" , and the name X is
	 * built in several places out of the name of a function and of an address. A hook whose second line adds an offset that
	 * belongs to another hook would still be valid javascript and would hook the wrong address.
	 */
	protected void check_the_two_variables_that_open_the_hook(OneHook hook)
	{
		String name_of_check="the variables that open one hook";
		expect_in_the_hook_code(name_of_check,hook,"var dynamic_address_of_"+hook.identifier+"=",
				"The address of a hook has to be declared under the same name as its offset");
		expect_in_the_hook_code(name_of_check,hook,"(offset_of_"+hook.identifier+")",
				"The address of a hook has to be computed from the offset that the same hook declared, and not from another one");

		/*
		 * The try/catch of a hook, when it was asked for. The plugin writes the opening and the closing of it in two different
		 * places, one before the call of the interceptor and one after it, so they are worth counting against each other.
		 */
		if (this.options.isIncludeInterceptorTryCatchcheckboxchecked.booleanValue())
		{
			String code_of_the_hook=hook.analyzer_of_the_hook.return_the_code_only_text();
			int how_many_tries=return_how_many_times_in(code_of_the_hook,"try {");
			int how_many_catches=return_how_many_times_in(code_of_the_hook,"catch(error)");
			this.report.count_one_check_that_was_run();
			if (how_many_tries!=how_many_catches)
			{
				this.report.add_error(name_of_check,"the try and the catch of one hook do not match",
						"One hook opens a different number of try blocks than it closes with a catch",
						"the hook of '"+hook.identifier+"' opens "+how_many_tries+" and catches "+how_many_catches,
						hook.line_where_it_starts)
					.with_the_context("the hook of "+hook.identifier,hook.text);
			}
		}
	}

	protected void check_the_options_that_write_inside_the_hook(OneHook hook)
	{
		String name_of_check="the options that write inside one hook";
		Boolean the_onEnter_was_asked_to_be_absent=Boolean.valueOf(this.options.isCustomFunInterceptorHookOutputCheckboxchecked.booleanValue()
				&& this.options.CustomFunInterceptorHookOutputcomboBox.getSelectedIndex()==0);
		Boolean the_onLeave_was_asked_to_be_absent=Boolean.valueOf(this.options.isCustomFunInterceptorHookOutputCheckboxchecked.booleanValue()
				&& this.options.CustomFunInterceptorHookOutputcomboBox.getSelectedIndex()==1);
		Boolean this_hook_has_an_onEnter=Boolean.valueOf(!hook.form.equals("function hook") || !the_onEnter_was_asked_to_be_absent.booleanValue());
		Boolean this_hook_has_an_onLeave=Boolean.valueOf(!hook.form.equals("function hook") || !the_onLeave_was_asked_to_be_absent.booleanValue());

		/*The reasons of the hooking, which are written where the onEnter would be*/
		if (this.options.isOutputReasonForHookGenCheckboxchecked.booleanValue())
		{
			if (this_hook_has_an_onEnter.booleanValue())
			{
				expect_in_the_hook(name_of_check,hook,"Reasons for hooking:","Every hook that has a beginning has to print why it was generated");
			}
			else
			{
				expect_not_in_the_hook(name_of_check,hook,"Reasons for hooking:","A hook that was asked to have no onEnter has nowhere to print its reasons");
			}
		}
		else
		{
			expect_not_in_the_hook(name_of_check,hook,"Reasons for hooking:","The option was off, so this hook must not print any reason");
		}

		/*The two custom texts, one of which goes into each half of the hook*/
		if (this.options.isIncludeCustomTextcheckboxchecked.booleanValue() && this_hook_has_an_onEnter.booleanValue())
		{
			String text_that_was_asked_for=this.options.IncludeCustomTextTextField.getText();
			if (text_that_was_asked_for!=null && !text_that_was_asked_for.trim().equals(""))
			{
				expect_in_the_hook(name_of_check,hook,text_that_was_asked_for,"The custom text that goes first has to be inside every hook that has a beginning");
			}
		}
		if (this.options.isIncludeCustomTextAftercheckboxchecked.booleanValue() && this_hook_has_an_onLeave.booleanValue()
				&& !hook.form.equals("address hook"))
		{
			String text_that_was_asked_for=this.options.IncludeCustomTextAfterTextField.getText();
			if (text_that_was_asked_for!=null && !text_that_was_asked_for.trim().equals(""))
			{
				expect_in_the_hook(name_of_check,hook,text_that_was_asked_for,"The custom text that goes last has to be inside every hook that has an end");
			}
		}

		/*
		 * The dictionary of the objects that the interceptor returned. An Interceptor.replace() returns nothing at all, so a
		 * replacement must never write into it: the entry would hold undefined and the script would look as if the hook could
		 * be detached through it.
		 */
		if (hook.form.equals("replacement"))
		{
			expect_not_in_the_hook_code(name_of_check,hook,"dict_with_objects_returned_from_attach[",
					"A replacement has no object to store, because Interceptor.replace() returns nothing");
		}
		else if (this.options.isCreateDataStructureWithInterceptorAttachObjectscheckboxchecked.booleanValue())
		{
			expect_in_the_hook_code(name_of_check,hook,"dict_with_objects_returned_from_attach[","A hook that attaches has to store the object that it got back");
		}

		/*
		 * The parameters of the function. The two options about them contradict one another, and the one that switches the
		 * printing off has to win: nothing may be printed even when the names were asked for as well.
		 */
		if (this.options.isDoNotIncludeFunParamscheckboxchecked.booleanValue())
		{
			/*
			 * Careful: what has to be absent is the printing of the parameters, not every use of the args[] array.
			 * A hook that was asked for the names of the parameters saves them with "this.arg_param_1=args[0];" so that the
			 * onLeave can still reach them, and that line is right even when the printing is switched off: the option refuses to
			 * print the parameters, it does not refuse to remember them. The two are told apart by the shape: the message is
			 * "args[0]=" or, when the names were asked for, "args[0](name)=", and neither of those ever appears in the line that
			 * saves the argument, which has the closing bracket followed by a semicolon.
			 *
			 * And the text of the hook, not its code, because the message is a string literal.
			 */
			expect_not_in_the_hook(name_of_check,hook,"args[0]=","The printing of the parameters was switched off, so no message may carry them");
			expect_not_in_the_hook(name_of_check,hook,"args[0](","The printing of the parameters was switched off, so no message may carry them together with their names");
		}

		/*
		 * The indentation of the log. The increase is written where the onEnter would be and the decrease where the onLeave
		 * would be, so a hook that has both halves has to have both, and one that has neither has to have neither.
		 *
		 * Careful: a hook that was asked to give up one of its two halves is expected to be left with only one of the two, and
		 * the indentation of that thread drifting for ever afterwards is the consequence of asking for such a hook. Every option
		 * whose code lives in the half that was taken away loses its effect the same way, which is why the demand is dropped
		 * here instead of being reported.
		 */
		if (this.options.isIncludeTIDAndIndentationcheckboxchecked.booleanValue()
				&& !the_onEnter_was_asked_to_be_absent.booleanValue() && !the_onLeave_was_asked_to_be_absent.booleanValue()
				&& !this.options.isGenerateNormalAddressHooksForFunctionBeginningscheckboxchecked.booleanValue())
		{
			int how_many_increases=return_how_many_times_in(hook.analyzer_of_the_hook.return_the_code_only_text(),"increase_indent()");
			int how_many_decreases=return_how_many_times_in(hook.analyzer_of_the_hook.return_the_code_only_text(),"decrease_indent()");
			this.report.count_one_check_that_was_run();
			if (how_many_increases!=how_many_decreases)
			{
				this.report.add_error(name_of_check,"the indentation of one hook is not balanced",
						"One hook increases the indentation of the log a different number of times than it decreases it, so the indentation of that thread drifts by two characters on every call and never comes back",
						"the hook of '"+hook.identifier+"' increases it "+how_many_increases+" times and decreases it "+how_many_decreases+" times",
						hook.line_where_it_starts)
					.with_the_context("the hook of "+hook.identifier,hook.text);
			}
		}
	}

	/*The whitespace at the beginning of the line that carries a piece of text, or null when the text is not in the hook*/
	protected String return_the_indentation_of_the_line_that_contains(OneHook hook,String needle)
	{
		int position=hook.text.indexOf(needle);
		if (position<0)
		{
			return null;
		}
		int start_of_the_line=position;
		while (start_of_the_line>0 && hook.text.charAt(start_of_the_line-1)!='\n')
		{
			start_of_the_line--;
		}
		int end_of_the_indentation=start_of_the_line;
		while (end_of_the_indentation<hook.text.length()
				&& (hook.text.charAt(end_of_the_indentation)==' ' || hook.text.charAt(end_of_the_indentation)=='\t'))
		{
			end_of_the_indentation++;
		}
		return hook.text.substring(start_of_the_line,end_of_the_indentation);
	}

	protected void check_a_function_hook(OneHook hook)
	{
		String name_of_check="the structure of a function hook";

		expect_in_the_hook_code(name_of_check,hook,"Interceptor.attach(dynamic_address_of_"+hook.identifier,
				"A function hook attaches to the address that it computed");
		expect_not_in_the_hook_code(name_of_check,hook,"Interceptor.replace(","A function hook attaches, it does not replace");
		expect_not_in_the_hook_code(name_of_check,hook,"function function_to_call_when_code_reaches_",
				"A function hook carries its code inside the object that it attaches, not in a function of its own");

		Boolean the_onEnter_was_asked_to_be_absent=Boolean.valueOf(this.options.isCustomFunInterceptorHookOutputCheckboxchecked.booleanValue()
				&& this.options.CustomFunInterceptorHookOutputcomboBox.getSelectedIndex()==0);
		Boolean the_onLeave_was_asked_to_be_absent=Boolean.valueOf(this.options.isCustomFunInterceptorHookOutputCheckboxchecked.booleanValue()
				&& this.options.CustomFunInterceptorHookOutputcomboBox.getSelectedIndex()==1);

		if (!the_onEnter_was_asked_to_be_absent.booleanValue())
		{
			expect_in_the_hook_code(name_of_check,hook,"onEnter: function(args)","A function hook has an onEnter that receives the arguments");
			expect_the_count_in_the_hook(name_of_check,hook,"onEnter:",1,"A function hook has exactly one onEnter");
			expect_in_the_hook(name_of_check,hook,"\"Entered "+hook.identifier+"\"","The onEnter announces the name of the function that was entered");
		}
		else
		{
			expect_not_in_the_hook_code(name_of_check,hook,"onEnter:","The form without an onEnter was asked for");
		}

		if (!the_onLeave_was_asked_to_be_absent.booleanValue())
		{
			expect_in_the_hook_code(name_of_check,hook,"onLeave: function(retval)","A function hook has an onLeave that receives the returned value");
			expect_the_count_in_the_hook(name_of_check,hook,"onLeave:",1,"A function hook has exactly one onLeave");
			expect_in_the_hook(name_of_check,hook,"\"Exited "+hook.identifier,"The onLeave announces the name of the function that was left");
			expect_in_the_hook_code(name_of_check,hook,"+retval","The onLeave prints the value that the function returned");
		}
		else
		{
			expect_not_in_the_hook_code(name_of_check,hook,"onLeave:","The form without an onLeave was asked for");
		}

		if (!the_onEnter_was_asked_to_be_absent.booleanValue() && !the_onLeave_was_asked_to_be_absent.booleanValue())
		{
			expect_the_first_before_the_second(name_of_check,hook,"onEnter:","onLeave:",
					"The onEnter of a hook has to be written before its onLeave");
			/*The object that is attached carries the two of them, separated by a comma*/
			expect_in_the_hook_code(name_of_check,hook,"},","The two halves of the object that is attached have to be separated");
		}

		/*
		 * The hint that shows how to change a register, and the one that shows how to change the returned value.
		 * Careful: the first of the two is written inside the onEnter, so a hook that was asked to have no onEnter does not
		 * carry it, and that is correct. The second one lives in the onLeave and follows the same reasoning.
		 */
		if (!the_onEnter_was_asked_to_be_absent.booleanValue())
		{
			expect_in_the_hook(name_of_check,hook,"// this.context.","A function hook carries the hint that shows how a register is changed");
		}
		if (!the_onLeave_was_asked_to_be_absent.booleanValue())
		{
			expect_in_the_hook(name_of_check,hook,"// retval.replace(","The onLeave carries the hint that shows how the returned value is changed");
		}

		/*The arguments belong to the onEnter, and there is no array of arguments anywhere else*/
		if (this.options.isDoNotIncludeFunParamscheckboxchecked.booleanValue())
		{
			expect_not_in_the_hook(name_of_check,hook,"args[0]=","The option that refuses to print the parameters was on");
		}
	}

	/*================================================================================================================
	 * an address hook: the form for an address that is not the beginning of a function
	 *==============================================================================================================*/

	protected void check_an_address_hook(OneHook hook)
	{
		String name_of_check="the structure of an address hook";

		expect_in_the_hook_code(name_of_check,hook,"function function_to_call_when_code_reaches_"+hook.identifier+"()",
				"An address hook declares the function that is called when the code reaches the address");
		expect_in_the_hook_code(name_of_check,hook,"Interceptor.attach(dynamic_address_of_"+hook.identifier+", function_to_call_when_code_reaches_"+hook.identifier+")",
				"An address hook attaches the very function that it declared, to the very address that it computed");
		/*
		 * Careful: the name appears twice, but the keyword "function" only comes before the declaration. Counting
		 * "function function_to_call_when_code_reaches_X" therefore always finds one, and it is the bare name that has to be
		 * counted.
		 */
		expect_the_count_in_the_hook(name_of_check,hook,"function_to_call_when_code_reaches_"+hook.identifier,2,
				"The function of an address hook is declared once and attached once, so its name appears twice");
		expect_the_first_before_the_second(name_of_check,hook,"function function_to_call_when_code_reaches_"+hook.identifier+"()","Interceptor.attach(",
				"The function of an address hook has to be declared before it is attached");

		expect_not_in_the_hook_code(name_of_check,hook,"onEnter:","An address hook is not a function hook");
		expect_not_in_the_hook_code(name_of_check,hook,"onLeave:","An address hook is not a function hook");
		expect_not_in_the_hook_code(name_of_check,hook,"Interceptor.replace(","An address hook attaches, it does not replace");
		expect_not_in_the_hook_code(name_of_check,hook,"new NativeFunction(","An address hook does not need the original function");

		expect_in_the_hook(name_of_check,hook,"Reached address","An address hook announces that the code reached the address");
		expect_in_the_hook(name_of_check,hook,"// this.context.","An address hook carries the hint that shows how a register is changed");

		/*The address that the hook announces has to be the address that it computed*/
		if (hook.address!=null)
		{
			this.report.count_one_check_that_was_run();
			if (hook.text.indexOf(hook.address.toString())<0)
			{
				this.report.add_error(name_of_check,"the address that is announced",
						"An address hook announces an address that is not the one it computed from its offset",
						"the hook of '"+hook.identifier+"' resolves to "+hook.address+" and does not mention it",hook.line_where_it_starts);
			}
		}
	}

	/*================================================================================================================
	 * a replacement: the form that replaces the function
	 *==============================================================================================================*/

	protected void check_a_replacement(OneHook hook)
	{
		String name_of_check="the structure of a replacement";

		expect_in_the_hook_code(name_of_check,hook,"var NativeFunction_of_"+hook.identifier+"= new NativeFunction(dynamic_address_of_"+hook.identifier,
				"A replacement keeps the original function, so that it can still be called");
		expect_in_the_hook_code(name_of_check,hook,"Interceptor.replace(dynamic_address_of_"+hook.identifier,
				"A replacement replaces the address that it computed");
		expect_in_the_hook_code(name_of_check,hook,"new NativeCallback(function(",
				"The callback of a replacement has to be a normal function, so that frida binds the invocation context to it");
		expect_not_in_the_hook_code(name_of_check,hook,"new NativeCallback((",
				"The callback of a replacement must not be an arrow function, it would have no context of its own");
		expect_not_in_the_hook_code(name_of_check,hook,"args[",
				"A NativeCallback has no array of arguments, its parameters are the ones of its own signature");
		expect_not_in_the_hook_code(name_of_check,hook,"onEnter:","A replacement has no onEnter, it is the function itself");
		expect_not_in_the_hook_code(name_of_check,hook,"onLeave:","A replacement has no onLeave, it is the function itself");
		expect_in_the_hook_code(name_of_check,hook,"var retval=NativeFunction_of_"+hook.identifier+"(",
				"A replacement calls the original function and keeps what it returned");
		expect_the_first_before_the_second(name_of_check,hook,"var NativeFunction_of_"+hook.identifier,"Interceptor.replace(",
				"The original function has to be kept before the replacement is installed");
		expect_in_the_hook(name_of_check,hook,"\"Entered "+hook.identifier+"\"","A replacement announces the name of the function that was entered");

		/*
		 * A replacement has to say that a value written into the context is ignored.
		 * The hint that suggests writing a register is shown in every other form of hook, where the write really does take
		 * effect, so a replacement that shows nothing at all is an invitation to write the same line and watch it do nothing.
		 */
		expect_in_the_hook(name_of_check,hook,"reading is fine, writing is not",
				"A replacement has to say that a value written into the context is ignored, because the callback takes the place of the function instead of running before it");
		expect_not_in_the_hook(name_of_check,hook,"//any register of the context can be read here, and a value written into one of them is put back",
				"The hint that promises that a write takes effect must never be shown inside a replacement");

		/*
		 * The two lists of types have to be the same one. The plugin writes them twice, once for the NativeFunction that
		 * keeps the original and once for the NativeCallback that replaces it, and a difference between them is a mismatch
		 * of the calling convention that nothing else would notice.
		 */
		/*
		 * A function that returns nothing must not end with a "return retval;", and one that returns something has to end
		 * with exactly one. The plugin decides this from the return type of the database, and the script says which one it
		 * wrote in the prototype of the NativeFunction that keeps the original.
		 */
		/*
		 * Careful: the text of the hook and not its code. The return type is written as a string literal, 'void' , and the code
		 * with the strings blanked out no longer carries the word, so reading it there finds nothing and every replacement of a
		 * function that returns nothing looks like one that returns something.
		 */
		String code_of_the_replacement=hook.analyzer_of_the_hook.return_the_code_only_text();
		if (hook.text.indexOf("new NativeFunction(dynamic_address_of_"+hook.identifier+",'void',")>=0)
		{
			expect_not_in_the_hook_code(name_of_check,hook,"return retval;",
					"The replaced function returns nothing, so the replacement must not return a value either");
		}
		else if (hook.text.indexOf("new NativeFunction(dynamic_address_of_"+hook.identifier+",")>=0)
		{
			expect_the_count_in_the_hook(name_of_check,hook,"return retval;",1,
					"The replaced function returns a value, so the replacement has to hand back exactly what the original returned");
		}

		/*
		 * The list of the parameters of the callback and the list of their types have to have the same number of entries. The
		 * plugin writes the two of them in two different places, from the same function of the database, and a difference
		 * between them is a call that frida marshals with the wrong number of arguments.
		 */
		String parameters_of_the_callback=return_the_text_between(code_of_the_replacement,"new NativeCallback(function(","){");
		String types_of_the_parameters=return_the_types_that_follow(code_of_the_replacement,"        },");
		this.report.count_one_check_that_was_run();
		if (parameters_of_the_callback!=null && !types_of_the_parameters.equals(""))
		{
			int how_many_parameters=return_how_many_entries_in_the_list(parameters_of_the_callback);
			int how_many_types=return_how_many_entries_in_the_list(types_of_the_parameters.replace("[","").replace("]",""));
			if (how_many_parameters!=how_many_types)
			{
				this.report.add_error(name_of_check,"the parameters and their types do not agree in number",
						"The callback of a replacement declares a number of parameters that is not the number of types that were written for it",
						"the callback takes "+how_many_parameters+" parameters ('"+parameters_of_the_callback+"') and "
						+how_many_types+" types were written ('"+types_of_the_parameters+"')",hook.line_where_it_starts)
					.with_the_context("the hook of "+hook.identifier,hook.text);
			}
		}

		String types_of_the_native_function=return_the_types_that_follow(hook.text,"new NativeFunction(dynamic_address_of_"+hook.identifier);
		String types_of_the_callback=return_the_types_that_follow(hook.text,"        },");
		this.report.count_one_check_that_was_run();
		if (!types_of_the_native_function.equals("") && !types_of_the_callback.equals("") && !types_of_the_native_function.equals(types_of_the_callback))
		{
			this.report.add_error(name_of_check,"the two lists of types disagree",
					"The types of the original function and the types of the replacement are not the same, which is a mismatch of the calling convention",
					"the original says '"+types_of_the_native_function+"' and the replacement says '"+types_of_the_callback+"'",hook.line_where_it_starts);
		}
	}

	/*Reads what follows a piece of text up to the end of that line, which is where the plugin writes the return type and the list of the types*/
	/*What is between two pieces of text, or null when either of them is not there*/
	protected String return_the_text_between(String text,String needle_before,String needle_after)
	{
		int position_of_the_first=text.indexOf(needle_before);
		if (position_of_the_first<0)
		{
			return null;
		}
		int start=position_of_the_first+needle_before.length();
		int position_of_the_second=text.indexOf(needle_after,start);
		if (position_of_the_second<0)
		{
			return null;
		}
		return text.substring(start,position_of_the_second);
	}

	/*How many entries a comma separated list has. An empty list has none, which is what a function with no parameters writes*/
	protected int return_how_many_entries_in_the_list(String list)
	{
		if (list==null || list.trim().equals(""))
		{
			return 0;
		}
		String[] the_entries=list.split(",");
		int retval=0;
		for (int i=0;i<the_entries.length;i++)
		{
			if (!the_entries[i].trim().equals(""))
			{
				retval++;
			}
		}
		return retval;
	}

	protected String return_the_types_that_follow(String text,String needle)
	{
		int position=text.indexOf(needle);
		if (position<0)
		{
			return "";
		}
		int position_of_the_bracket=text.indexOf("[",position);
		if (position_of_the_bracket<0)
		{
			return "";
		}
		int position_of_the_closing_bracket=text.indexOf("]",position_of_the_bracket);
		if (position_of_the_closing_bracket<0)
		{
			return "";
		}
		return text.substring(position_of_the_bracket,position_of_the_closing_bracket+1);
	}

	/*================================================================================================================
	 * one hook against the database
	 *==============================================================================================================*/

	protected void check_a_hook_against_the_database(OneHook hook)
	{
		String name_of_check="one hook against the database";
		if (hook.address==null)
		{
			return;
		}
		Listing listing=this.current_program.getListing();

		/*The plugin only ever hooks the first byte of an instruction*/
		this.report.count_one_check_that_was_run();
		if (listing.getInstructionAt(hook.address)==null)
		{
			this.report.add_error(name_of_check,"a hook that is not on an instruction",
					"A hook sits on an address at which the database has no instruction",
					"the hook of '"+hook.identifier+"' resolves to "+hook.address,hook.line_where_it_starts);
			return;
		}

		/*
		 * What the message of the hook claims about the function it sits in, against what the database says.
		 * An address that no function owns is a branch of its own in the generator: there is no name to put in the message and no
		 * beginning of a function to write into the dictionaries, so it writes the words "not in a function". A hook that claims a
		 * function it is not in would send the reader of the log looking in the wrong place.
		 */
		Function function_containing_the_address=this.current_program.getFunctionManager().getFunctionContaining(hook.address);
		this.report.count_one_check_that_was_run();
		if (function_containing_the_address==null && hook.text.indexOf("which is inside function")>=0)
		{
			this.report.add_error(name_of_check,"a hook that claims a function it is not in",
					"A hook says that its address is inside a function, and the database has no function containing that address",
					"the hook of '"+hook.identifier+"' resolves to "+hook.address,hook.line_where_it_starts)
				.with_the_context("the hook of "+hook.identifier,hook.text);
		}
		this.report.count_one_check_that_was_run();
		if (function_containing_the_address!=null && hook.text.indexOf("not in a function")>=0)
		{
			this.report.add_error(name_of_check,"a hook that denies the function it is in",
					"A hook says that its address is in no function, and the database has one containing that address",
					"the hook of '"+hook.identifier+"' resolves to "+hook.address+" , which is inside "
					+function_containing_the_address.getName(),hook.line_where_it_starts)
				.with_the_context("the hook of "+hook.identifier,hook.text);
		}

		Function function_at_the_address=this.current_program.getFunctionManager().getFunctionAt(hook.address);

		/*A hook that was written in one of the two forms for a function has to sit on the beginning of a function*/
		if (hook.form.equals("function hook") || hook.form.equals("replacement"))
		{
			this.report.count_one_check_that_was_run();
			if (function_at_the_address==null)
			{
				this.report.add_error(name_of_check,"a function hook that is not on a function",
						"A hook was written in the form that is meant for the beginning of a function, but the database has no function at that address",
						"the hook of '"+hook.identifier+"' resolves to "+hook.address,hook.line_where_it_starts);
			}
			else
			{
				/*And the name that the hook carries has to be the name that the database has*/
				String sanitized_name_of_the_function=function_at_the_address.getName(true).replaceAll("[^"+this.characters_allowed_in_variable_name+"]","_");
				this.report.count_one_check_that_was_run();
				if (!hook.identifier.startsWith(sanitized_name_of_the_function+"_"))
				{
					this.report.add_error(name_of_check,"the name of a hook and the name of the function",
							"The name that a hook carries is not built from the name that the database has for the function at that address",
							"the hook is named '"+hook.identifier+"' and the database says the function is '"+sanitized_name_of_the_function+"'",hook.line_where_it_starts);
				}

				/*And it must not print more arguments than the function has*/
				check_that_the_hook_does_not_print_more_arguments_than_there_are(hook,function_at_the_address);
			}
		}

		/*A hook in the form for an ordinary address must not be sitting on the beginning of a function, unless the user asked for exactly that*/
		if (hook.form.equals("address hook") && function_at_the_address!=null)
		{
			Boolean the_user_asked_for_this=Boolean.valueOf(this.options.isGenerateNormalAddressHooksForFunctionBeginningscheckboxchecked.booleanValue());
			this.report.count_one_check_that_was_run();
			if (!the_user_asked_for_this.booleanValue())
			{
				this.report.add_warning(name_of_check,"an address hook on a function beginning",
						"A hook was written in the form that is meant for an ordinary address, but the database says a function begins there, and the option that asks for that was not on",
						"the hook of '"+hook.identifier+"' resolves to "+hook.address,hook.line_where_it_starts);
			}
		}
	}

	protected void check_that_the_hook_does_not_print_more_arguments_than_there_are(OneHook hook,Function function)
	{
		this.report.count_one_check_that_was_run();
		int how_many_parameters_the_database_has=function.getParameterCount();
		/*The largest index of an argument that the hook prints*/
		int largest_index_that_is_printed=-1;
		int position=hook.text.indexOf("args[");
		while (position>=0)
		{
			int start_of_the_digits=position+"args[".length();
			int j=start_of_the_digits;
			while (j<hook.text.length() && Character.isDigit(hook.text.charAt(j)))
			{
				j++;
			}
			if (j>start_of_the_digits)
			{
				try {
					int index=Integer.parseInt(hook.text.substring(start_of_the_digits,j));
					if (index>largest_index_that_is_printed)
					{
						largest_index_that_is_printed=index;
					}
				}
				catch (NumberFormatException ex)
				{
					//an index that is not a number, nothing to compare
				}
			}
			position=hook.text.indexOf("args[",position+1);
		}
		if (largest_index_that_is_printed>=0 && largest_index_that_is_printed>=how_many_parameters_the_database_has)
		{
			this.report.add_error("one hook against the database","more arguments than the function has",
					"A hook prints an argument that the function does not have",
					"the hook of '"+hook.identifier+"' prints args["+largest_index_that_is_printed+"] and the database says the function has "+how_many_parameters_the_database_has+" parameters",
					hook.line_where_it_starts);
		}
	}

	/*================================================================================================================
	 * the hooks taken together
	 *==============================================================================================================*/

	/*
	 * Two hooks must never share a name, because the second declaration would silently replace the first, and they must
	 * never share an address, because the plugin is supposed to hook every address once and only once.
	 */
	protected void check_that_no_two_hooks_share_a_name_or_an_address(ArrayList<OneHook> the_hooks)
	{
		LinkedHashMap<String,Integer> how_many_times_a_name_is_used=new LinkedHashMap<String,Integer>();
		LinkedHashMap<String,Integer> how_many_times_an_offset_is_used=new LinkedHashMap<String,Integer>();

		for (int i=0;i<the_hooks.size();i++)
		{
			OneHook hook=the_hooks.get(i);
			if (!hook.identifier.equals(""))
			{
				Integer how_many=how_many_times_a_name_is_used.get(hook.identifier);
				how_many_times_a_name_is_used.put(hook.identifier,Integer.valueOf(how_many==null?1:how_many.intValue()+1));
			}
			if (!hook.hexadecimal_of_the_offset.equals(""))
			{
				String key=(hook.the_offset_is_subtracted.booleanValue()?"-":"+")+hook.hexadecimal_of_the_offset;
				Integer how_many=how_many_times_an_offset_is_used.get(key);
				how_many_times_an_offset_is_used.put(key,Integer.valueOf(how_many==null?1:how_many.intValue()+1));
			}
		}

		for (String identifier: how_many_times_a_name_is_used.keySet())
		{
			this.report.count_one_check_that_was_run();
			if (how_many_times_a_name_is_used.get(identifier).intValue()>1)
			{
				this.report.add_error("the hooks taken together","two hooks with the same name",
						"Two hooks of the same script are built on the same name, so the second one silently replaces the variables of the first",
						"the name '"+identifier+"' is used by "+how_many_times_a_name_is_used.get(identifier)+" hooks",0);
			}
		}
		for (String key: how_many_times_an_offset_is_used.keySet())
		{
			this.report.count_one_check_that_was_run();
			if (how_many_times_an_offset_is_used.get(key).intValue()>1)
			{
				this.report.add_error("the hooks taken together","two hooks on the same address",
						"Two hooks of the same script sit on the same address, and every address is supposed to be hooked once",
						"the offset "+key+" is hooked by "+how_many_times_an_offset_is_used.get(key)+" hooks",0);
			}
		}
	}

	/*A hook that is written after the interceptors have been flushed would never be registered*/
	protected void check_that_nothing_comes_after_the_flush(ArrayList<OneHook> the_hooks)
	{
		String code=this.analyzer.return_the_code_only_text();
		int position_of_the_flush=code.indexOf("Interceptor.flush()");
		if (position_of_the_flush<0)
		{
			return;
		}
		for (int i=0;i<the_hooks.size();i++)
		{
			this.report.count_one_check_that_was_run();
			if (the_hooks.get(i).position_where_it_starts>position_of_the_flush)
			{
				this.report.add_error("the hooks taken together","a hook after the flush",
						"A hook is written after the interceptors were flushed, so it would never be registered",
						"the hook of '"+the_hooks.get(i).identifier+"'",the_hooks.get(i).line_where_it_starts);
			}
		}
	}
}
