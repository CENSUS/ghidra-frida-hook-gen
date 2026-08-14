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
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;

/*
 * Looks at one generated script and decides whether it makes sense.
 *
 * There are three kinds of check here, and they find different kinds of problem:
 *
 *  - The structural ones. Can this text even be javascript: are the braces balanced, is every name a name that
 *    javascript accepts, does the script refer to something that it never declares, is there an assignment with nothing
 *    on its right hand side. These are the ones that catch a marker that was never replaced, an address that carried the
 *    name of its address space into an identifier, and an operand that could not be translated.
 *
 *  - The ones that know how this plugin writes its hooks. A NativeCallback has no args[] array. The tolerance for the
 *    names of the Windows modules must never be applied outside a check on Process.platform. A script has exactly one
 *    Interceptor.flush(). These encode the mistakes that have actually been made in this code, so that they cannot come
 *    back unnoticed.
 *
 *  - The ones that ask the database. Every offset that the script computes is turned back into an address and looked up:
 *    is there really an instruction there, is the function that the hook is named after really at that address, are all
 *    the functions that were asked for actually present. This is the part that can tell that the generated script is
 *    valid javascript which hooks the wrong things.
 */
public class GeneratedScriptChecker {

	protected Program current_program;
	protected SelfTestReport report;
	protected String sanitized_name_of_the_program;
	protected String characters_allowed_in_variable_name="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";

	/*
	 * The names that the prologue of a whole script declares. A snippet is meant to be pasted into a script that already has
	 * that prologue, so it uses them without declaring them and that is not a mistake. A whole script has to declare every one
	 * of them itself, and there the absence of a declaration is a real defect, which is why this list is only allowed through
	 * when the script under examination carries no prologue.
	 */
	protected static final String[] names_that_the_prologue_of_a_whole_script_declares={
		"tid_and_indent","increase_indent","decrease_indent","dict_with_thread_indentation_levels",
		"dict_with_objects_returned_from_attach","dict_from_current_addresses_to_function_names",
		"dict_from_function_names_to_function_start_addresses","dict_from_current_addresses_to_function_start_addresses",
		"dict_from_function_start_addresses_to_function_names","current_function_start_address",
		"counter_for_successful_Interceptor_hooks","counter_for_failed_Interceptor_hooks","modulemap_for_all_modules",
		"register_interceptors","start_timer_for_intercept","do_the_dlopen_interception","do_the_loadlibrary_interception",
		"extract_libname_from_dlopen_arg","extract_libname_from_loadlibrary_arg"
	};

	/*The names that the generated script is allowed to use without declaring them: what javascript and what frida provide*/
	protected static final String[] names_that_are_provided_by_javascript_or_frida={
		/*javascript keywords and the values that look like names, which the reader of the text cannot tell apart from a variable*/
		"var","let","const","function","return","if","else","for","while","do","break","continue","switch","case","default",
		"try","catch","finally","throw","typeof","instanceof","in","of","delete","void","new","this","class","extends",
		"super","yield","await","async","null","true","false","undefined","arguments","NaN","Infinity","globalThis",
		/*the standard library*/
		"console","JSON","Math","Object","Array","String","Number","Boolean","Date","RegExp","Error","Promise","Symbol",
		"Map","Set","WeakMap","WeakSet","parseInt","parseFloat","isNaN","isFinite","setTimeout","setInterval",
		"clearTimeout","clearInterval",
		/*what frida provides*/
		"Interceptor","Process","Module","ModuleMap","Memory","MemoryAccessMonitor","NativeFunction","NativeCallback",
		"NativePointer","ptr","int64","uint64","Thread","Backtracer","DebugSymbol","ApiResolver","Instruction","Stalker",
		"Kernel","CModule","Script","File","Socket","SqliteDatabase","Java","ObjC","send","recv","rpc","hexdump","gc",
		"WeakRef","Frida","MatchPattern"
	};

	/*How many hooks of the script are examined one by one, and how many things a check enumerates from the database. Both are what the level of the self test decides*/
	protected int how_many_hooks_to_examine;
	protected int how_many_things_to_enumerate_from_the_database;

	public GeneratedScriptChecker(Program current_program,SelfTestReport report)
	{
		this(current_program,report,25,25);
	}

	public GeneratedScriptChecker(Program current_program,SelfTestReport report,int how_many_hooks_to_examine,int how_many_things_to_enumerate_from_the_database)
	{
		this.current_program=current_program;
		this.report=report;
		this.how_many_hooks_to_examine=how_many_hooks_to_examine;
		this.how_many_things_to_enumerate_from_the_database=how_many_things_to_enumerate_from_the_database;
		this.sanitized_name_of_the_program=current_program.getName().replaceAll("[^"+this.characters_allowed_in_variable_name+"]","_");
	}

	/*
	 * What the caller expects to find in the script it just generated. Everything is optional: a check is only made when
	 * the corresponding expectation was filled in, so a combination only pays for the checks that apply to it.
	 */
	public static class Expectations
	{
		public Boolean the_script_has_a_prologue=false;		//the "generate script" option was on
		public ArrayList<Address> addresses_that_must_be_hooked=new ArrayList<Address>();
		public String regex_of_function_names_that_must_be_hooked="";
		public Boolean every_exported_entry_point_must_be_hooked=false;
		public Boolean the_interceptor_replace_form_is_expected=false;
		public Boolean the_onEnter_is_expected_to_be_absent=false;
		public String text_that_must_appear_somewhere="";	//for example a piece of custom text that the user asked for
		public ArrayList<Address> addresses_that_must_not_be_hooked=new ArrayList<Address>();	//for when the user unticked the option that hooks the address that was selected
	}

	/*
	 * Runs every check that applies. Returns how many errors were reported for this script.
	 * The options are handed over as well, because half of the checks are about one option each: what that option has to
	 * put inside the script when it is on, and what must not be there when it is off.
	 */
	public int check_the_generated_script(String script,Expectations expectations,fridahookgenerator.AdvancedHookOptionsDialog options,Address seed_address)
	{
		int how_many_errors_before=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR);

		if (script==null || script.trim().equals(""))
		{
			this.report.add_error("empty output","empty","The generator returned nothing at all","the returned string was empty",0);
			return 1;
		}

		JavascriptTextAnalyzer analyzer=new JavascriptTextAnalyzer(script);

		check_that_no_marker_survived(analyzer);
		check_that_the_brackets_are_balanced(analyzer);
		check_that_there_is_no_empty_assignment(analyzer);
		check_that_there_is_no_call_with_nothing_inside_it(analyzer);
		check_that_every_declared_name_is_a_name(analyzer);
		check_that_nothing_is_used_without_being_declared(analyzer,expectations);
		check_that_no_offset_looks_like_a_negative_number(analyzer);
		check_that_no_backtrace_is_taken_without_a_context(analyzer);
		check_the_hints_that_name_a_register(analyzer);
		check_the_shape_of_the_interceptor_replace_hooks(analyzer);
		check_that_the_windows_tolerance_is_guarded(analyzer);
		check_the_module_name_helper(analyzer);
		check_the_prologue_and_the_epilogue(analyzer,expectations);
		check_the_hooked_addresses_against_the_database(analyzer,expectations);
		check_that_the_requested_addresses_are_there(analyzer,expectations);
		check_that_the_refused_addresses_are_not_there(analyzer,expectations);
		check_that_the_requested_functions_are_there(analyzer,expectations);
		check_that_the_exported_entry_points_are_there(analyzer,expectations);
		check_the_custom_text(analyzer,expectations);

		/*And now the checks that belong to one option each, and the ones that look at every hook on its own*/
		if (options!=null)
		{
			new OptionSpecificChecks(this.current_program,this.report,options,analyzer,seed_address,this.how_many_things_to_enumerate_from_the_database).run_all_the_checks_that_the_options_ask_for();
			new PerHookChecks(this.current_program,this.report,options,analyzer,this.how_many_hooks_to_examine).run_all_the_checks_on_every_hook();
		}

		int how_many_errors_after=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR);
		return how_many_errors_after-how_many_errors_before;
	}

	/*----------------------------------------------------------------------------------------------------------------
	 * structural checks
	 *--------------------------------------------------------------------------------------------------------------*/

	/*A marker that was not replaced is the symptom of the two halves of the backpatching disagreeing with each other*/
	protected void check_that_no_marker_survived(JavascriptTextAnalyzer analyzer)
	{
		this.report.count_one_check_that_was_run();
		String[] markers={"PLACEHOLDER_FOR_HOOK_CODE_TO_BE_ADDED_LATER_","PLACEHOLDER_FOR_REASONS_FOR_HOOKING_","PLACEHOLDER"};
		for (int i=0;i<markers.length;i++)
		{
			ArrayList<Integer> positions=analyzer.return_the_positions_anywhere_of(markers[i]);
			for (int j=0;j<positions.size();j++)
			{
				int position=positions.get(j).intValue();
				this.report.add_error("markers left in the script",markers[i],
						"A placeholder of the generator was left inside the generated script ("+markers[i]+")",
						analyzer.return_the_line_at_the_position(position),
						analyzer.return_the_line_number_of_the_position(position));
			}
			if (positions.size()>0)
			{
				return;	//the first marker that is found says everything, no need to report the shorter forms of the same text
			}
		}
	}

	protected void check_that_the_brackets_are_balanced(JavascriptTextAnalyzer analyzer)
	{
		this.report.count_one_check_that_was_run();
		char[][] pairs={{'{','}'},{'(',')'},{'[',']'}};
		for (int i=0;i<pairs.length;i++)
		{
			char opening=pairs[i][0];
			char closing=pairs[i][1];
			int balance=analyzer.return_the_balance_of(opening,closing);
			if (balance!=0)
			{
				this.report.add_error("brackets are not balanced",""+opening,
						"The script has "+Math.abs(balance)+" more "+(balance>0?("unclosed '"+opening+"'"):("'"+closing+"' than it opened")),
						"counted over the code only, with the comments and the strings ignored",0);
			}
			int position_where_it_goes_negative=analyzer.return_the_position_where_the_balance_goes_negative(opening,closing);
			if (position_where_it_goes_negative>=0)
			{
				this.report.add_error("brackets are not balanced",""+opening+"negative",
						"The script closes a '"+closing+"' that was never opened",
						analyzer.return_the_line_at_the_position(position_where_it_goes_negative),
						analyzer.return_the_line_number_of_the_position(position_where_it_goes_negative));
			}
		}
	}

	/*"var x= ;" is what an operand that could not be translated used to produce*/
	protected void check_that_there_is_no_empty_assignment(JavascriptTextAnalyzer analyzer)
	{
		this.report.count_one_check_that_was_run();
		String code=analyzer.return_the_code_only_text();
		for (int i=0;i<code.length();i++)
		{
			if (code.charAt(i)!='=')
			{
				continue;
			}
			/*Skip the comparisons and the arrow, only a plain assignment is of interest*/
			if (i+1<code.length() && (code.charAt(i+1)=='=' || code.charAt(i+1)=='>'))
			{
				continue;
			}
			if (i>0 && (code.charAt(i-1)=='=' || code.charAt(i-1)=='!' || code.charAt(i-1)=='<' || code.charAt(i-1)=='>' || code.charAt(i-1)=='+' || code.charAt(i-1)=='-'))
			{
				continue;
			}
			int j=i+1;
			while (j<code.length() && (code.charAt(j)==' ' || code.charAt(j)=='\t'))
			{
				j++;
			}
			if (j<code.length() && (code.charAt(j)==';' || code.charAt(j)=='\n'))
			{
				this.report.add_error("assignment with nothing on its right","empty assignment",
						"The script assigns nothing to a variable, which means a piece of code was expected there and was not produced",
						analyzer.return_the_line_at_the_position(i),
						analyzer.return_the_line_number_of_the_position(i));
			}
		}
	}

	/*".add()" with nothing inside is what an empty term of an address expression used to produce*/
	protected void check_that_there_is_no_call_with_nothing_inside_it(JavascriptTextAnalyzer analyzer)
	{
		this.report.count_one_check_that_was_run();
		String[] calls_that_need_an_argument={".add()",".sub()",".and()",".or()",".shr()",".shl()",".strip()"};
		for (int i=0;i<calls_that_need_an_argument.length;i++)
		{
			ArrayList<Integer> positions=analyzer.return_the_positions_in_the_code_of(calls_that_need_an_argument[i]);
			for (int j=0;j<positions.size();j++)
			{
				int position=positions.get(j).intValue();
				this.report.add_error("call without its argument",calls_that_need_an_argument[i],
						"The script calls "+calls_that_need_an_argument[i]+" with nothing inside it, so a term of an address expression was lost",
						analyzer.return_the_line_at_the_position(position),
						analyzer.return_the_line_number_of_the_position(position));
			}
		}
	}

	/*
	 * An address that belongs to an address space other than the default one carries the name of that space and a colon,
	 * and that colon cannot be part of a javascript name. The symptom is a declaration whose name is followed by a colon.
	 */
	protected void check_that_every_declared_name_is_a_name(JavascriptTextAnalyzer analyzer)
	{
		this.report.count_one_check_that_was_run();
		String code=analyzer.return_the_code_only_text();
		String[] keywords={"var ","let ","const ","function "};
		for (int k=0;k<keywords.length;k++)
		{
			ArrayList<Integer> positions=analyzer.return_the_positions_in_the_code_of(keywords[k]);
			for (int j=0;j<positions.size();j++)
			{
				int position_after_the_keyword=positions.get(j).intValue()+keywords[k].length();
				int i=position_after_the_keyword;
				while (i<code.length() && (code.charAt(i)==' ' || code.charAt(i)=='\t'))
				{
					i++;
				}
				int start_of_the_name=i;
				while (i<code.length() && JavascriptTextAnalyzer.is_a_character_that_can_be_inside_a_name(code.charAt(i)).booleanValue())
				{
					i++;
				}
				if (i==start_of_the_name)
				{
					continue;
				}
				if (i<code.length() && code.charAt(i)==':')
				{
					this.report.add_error("a name that javascript will not accept","colon in a name",
							"A declared name is followed by a colon, which means something that is not a name ended up inside an identifier (an address of a non default address space does that)",
							analyzer.return_the_line_at_the_position(start_of_the_name),
							analyzer.return_the_line_number_of_the_position(start_of_the_name));
				}
			}
		}
	}

	/*
	 * Every name the script uses has to come from somewhere: it is declared by the script, or javascript or frida provide
	 * it. Anything else is either a marker that was never replaced, or a variable whose name was built differently in the
	 * two places that mention it.
	 */
	protected void check_that_nothing_is_used_without_being_declared(JavascriptTextAnalyzer analyzer,Expectations expectations)
	{
		this.report.count_one_check_that_was_run();
		LinkedHashSet<String> declared_names=analyzer.return_all_the_declared_names();
		LinkedHashSet<String> names_that_are_allowed=new LinkedHashSet<String>();
		for (int i=0;i<names_that_are_provided_by_javascript_or_frida.length;i++)
		{
			names_that_are_allowed.add(names_that_are_provided_by_javascript_or_frida[i]);
		}
		/*
		 * Careful: a snippet is meant to be pasted into a script that already declares the name of the module, so it refers
		 * to that variable without declaring it and that is not a mistake. A whole script does declare it, and the check on
		 * the prologue is the one that makes sure of it.
		 */
		names_that_are_allowed.add("module_name_"+this.sanitized_name_of_the_program);
		if (expectations==null || !expectations.the_script_has_a_prologue.booleanValue())
		{
			/*
			 * The rest of what the prologue provides, for the same reason. A snippet that was generated with the thread
			 * identifiers or with the dictionaries switched on uses tid_and_indent() and the dictionaries without carrying
			 * them, and it is the script that the user pastes it into that has them.
			 */
			for (int i=0;i<names_that_the_prologue_of_a_whole_script_declares.length;i++)
			{
				names_that_are_allowed.add(names_that_the_prologue_of_a_whole_script_declares[i]);
			}
		}

		ArrayList<JavascriptTextAnalyzer.NameThatIsReferred> names_that_are_referred=analyzer.return_all_the_names_that_are_referred_to();
		LinkedHashSet<String> already_reported=new LinkedHashSet<String>();
		for (int i=0;i<names_that_are_referred.size();i++)
		{
			JavascriptTextAnalyzer.NameThatIsReferred reference=names_that_are_referred.get(i);
			if (declared_names.contains(reference.name) || names_that_are_allowed.contains(reference.name))
			{
				continue;
			}
			if (already_reported.contains(reference.name))
			{
				continue;	//one report per name is enough, the report collapses the rest anyway
			}
			already_reported.add(reference.name);
			this.report.add_error("a name that is never declared",reference.name,
					"The script uses '"+reference.name+"' without ever declaring it",
					analyzer.return_the_line_at_the_position(reference.position),
					analyzer.return_the_line_number_of_the_position(reference.position));
		}
	}

	/*
	 * An offset from the base of the module that was rendered as an unsigned number: the symptom is a hexadecimal that is
	 * far too large to be an offset inside a module.
	 */
	protected void check_that_no_offset_looks_like_a_negative_number(JavascriptTextAnalyzer analyzer)
	{
		this.report.count_one_check_that_was_run();
		String code=analyzer.return_the_code_only_text();
		int position=code.indexOf("0x");
		while (position>=0)
		{
			int i=position+2;
			int start_of_the_digits=i;
			while (i<code.length() && is_a_hexadecimal_digit(code.charAt(i)))
			{
				i++;
			}
			String digits=code.substring(start_of_the_digits,i);
			/*Twelve digits or more is at least a terabyte of offset, which no module has. Sixteen digits starting with f is the classic rendering of a negative number*/
			if (digits.length()>=12)
			{
				this.report.add_error("an offset that cannot be an offset","huge offset",
						"The script uses the value 0x"+digits+" as an offset, which is far too large. A negative number that was printed as unsigned looks exactly like this",
						analyzer.return_the_line_at_the_position(position),
						analyzer.return_the_line_number_of_the_position(position));
			}
			position=code.indexOf("0x",position+2);
		}
	}

	protected Boolean is_a_hexadecimal_digit(char c)
	{
		return Boolean.valueOf((c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F'));
	}

	/*----------------------------------------------------------------------------------------------------------------
	 * checks that know how this plugin writes its hooks
	 *--------------------------------------------------------------------------------------------------------------*/

	/*
	 * A NativeCallback has no args[] array, its parameters are the ones that were declared in its signature, and it has to
	 * be a normal function so that frida can bind the invocation context to it.
	 */
	/*
	 * An address that the caller said must not be hooked has to be in no hook of the script.
	 * The option that hooks the address the dialog was opened on can be unticked, and then the script is supposed to carry only
	 * what the other options collected. An address that is hooked although it was not asked for is a hook the user did not want,
	 * and it is the kind of thing that only shows when one option is off while the others are on.
	 */
	protected void check_that_the_refused_addresses_are_not_there(JavascriptTextAnalyzer analyzer,Expectations expectations)
	{
		if (expectations==null || expectations.addresses_that_must_not_be_hooked.size()==0)
		{
			return;
		}
		String name_of_check="the addresses that had to be left alone";
		for (int i=0;i<expectations.addresses_that_must_not_be_hooked.size();i++)
		{
			Address address=expectations.addresses_that_must_not_be_hooked.get(i);
			this.report.count_one_check_that_was_run();
			long offset_from_the_image_base=address.getOffset()-this.current_program.getImageBase().getOffset();
			String offset_as_it_would_be_written="="+fridahookgenerator.HookGeneratorUtils.return_hex_str_for_absolute_value_of_offset(offset_from_the_image_base)+";";
			/*
			 * Careful: the offset has to be found on a line that declares the offset of a hook, and not just anywhere in the code.
			 * The same hexadecimal number can be written for other reasons, and a hook is the only thing that would mean the
			 * address really is hooked.
			 */
			ArrayList<Integer> the_positions=new ArrayList<Integer>();
			ArrayList<Integer> the_positions_of_the_number=analyzer.return_the_positions_in_the_code_of(offset_as_it_would_be_written);
			for (int j=0;j<the_positions_of_the_number.size();j++)
			{
				if (analyzer.return_the_line_at_the_position(the_positions_of_the_number.get(j).intValue()).startsWith("var offset_of_"))
				{
					the_positions.add(the_positions_of_the_number.get(j));
				}
			}
			if (the_positions.size()>0)
			{
				this.report.add_error(name_of_check,"an address that was not asked for is hooked",
						"The script hooks an address that the options did not ask for",
						"the address "+address+" is hooked, although the option that hooks the address of the dialog was off",
						analyzer.return_the_line_number_of_the_position(the_positions.get(0).intValue()))
					.with_the_context("the line",analyzer.return_the_line_at_the_position(the_positions.get(0).intValue()));
			}
		}
	}

	/*
	 * The hints that suggest how a register is changed name a register, and it has to be a register that the processor of the
	 * program actually has. The hint used to name x0 whatever the program was, so every hook generated for an x86 target
	 * suggested writing into a register of a different architecture.
	 * Careful: the name is worked out here from the language of the program on purpose, instead of being asked of the plugin.
	 * A check that asks the code under test what the right answer is cannot fail.
	 */
	protected void check_the_hints_that_name_a_register(JavascriptTextAnalyzer analyzer)
	{
		String name_of_check="the hints that name a register";
		this.report.count_one_check_that_was_run();
		String identifier_of_the_language=this.current_program.getLanguage().getLanguageID().toString();
		String name_that_is_expected="";
		if (identifier_of_the_language.indexOf("AARCH64")>=0) { name_that_is_expected="x0"; }
		else if (identifier_of_the_language.indexOf("ARM")>=0) { name_that_is_expected="r0"; }
		else if (identifier_of_the_language.indexOf("x86")>=0 && identifier_of_the_language.indexOf(":64:")>=0) { name_that_is_expected="rax"; }
		else if (identifier_of_the_language.indexOf("x86")>=0) { name_that_is_expected="eax"; }
		else if (identifier_of_the_language.indexOf("MIPS")>=0) { name_that_is_expected="a0"; }
		else if (identifier_of_the_language.indexOf("PowerPC")>=0) { name_that_is_expected="r3"; }
		else
		{
			/*
			 * A processor that this check does not know either. The plugin writes a placeholder for exactly those, so the hint has
			 * to carry the placeholder and not a name that was guessed.
			 */
			name_that_is_expected="<name of the register>";
		}

		String prefix_of_the_hint="// this.context.";
		ArrayList<Integer> the_positions=analyzer.return_the_positions_anywhere_of(prefix_of_the_hint);
		for (int i=0;i<the_positions.size();i++)
		{
			int position_of_the_name=the_positions.get(i).intValue()+prefix_of_the_hint.length();
			String name_that_was_found="";
			int j=position_of_the_name;
			/*The placeholder that an unknown processor gets is not made of the characters of a name, so it is read as a whole*/
			if (analyzer.return_the_original_text().startsWith("<name of the register>",position_of_the_name))
			{
				name_that_was_found="<name of the register>";
			}
			else
			{
				while (j<analyzer.return_the_original_text().length()
						&& this.characters_allowed_in_variable_name.indexOf(analyzer.return_the_original_text().charAt(j))>=0)
				{
					name_that_was_found+=analyzer.return_the_original_text().charAt(j);
					j++;
				}
			}
			if (!name_that_was_found.equals(name_that_is_expected))
			{
				this.report.add_error(name_of_check,"a hint that names a register of another architecture",
						"A hint suggests writing into a register that the processor of this program does not have",
						"the language is "+identifier_of_the_language+", so '"+name_that_is_expected+"' was expected and '"
						+name_that_was_found+"' was found",analyzer.return_the_line_number_of_the_position(the_positions.get(i).intValue()))
					.with_the_context("the line",analyzer.return_the_line_at_the_position(the_positions.get(i).intValue()));
			}
		}
	}

	/*
	 * Not one backtrace of the script may be taken with a null context, whatever the options were and whatever hook it sits
	 * in. This is here as well as in the checks of the option, because a script that was generated with a combination that
	 * this suite does not know about still has to obey it.
	 */
	protected void check_that_no_backtrace_is_taken_without_a_context(JavascriptTextAnalyzer analyzer)
	{
		String name_of_check="the context of the backtracer";
		ArrayList<Integer> the_positions=analyzer.return_the_positions_in_the_code_of("Thread.backtrace(null");
		for (int i=0;i<the_positions.size();i++)
		{
			int position=the_positions.get(i).intValue();
			this.report.add_error(name_of_check,"a backtrace with a null context",
					"A backtrace is taken with a null context, so it unwinds from frida's own frames instead of from the hooked place, and the accurate backtracer loses the caller",
					"Thread.backtrace(this.context, ...) was expected",analyzer.return_the_line_number_of_the_position(position))
				.with_the_context("the line",analyzer.return_the_line_at_the_position(position));
		}
		this.report.count_one_check_that_was_run();
	}

	protected void check_the_shape_of_the_interceptor_replace_hooks(JavascriptTextAnalyzer analyzer)
	{
		this.report.count_one_check_that_was_run();
		ArrayList<Integer> positions=analyzer.return_the_positions_in_the_code_of("Interceptor.replace(");
		for (int i=0;i<positions.size();i++)
		{
			int position=positions.get(i).intValue();
			/*Careful: the code of the call, not its text, or the args[0] that a hook prints inside a message is mistaken for a use of args[]*/
			String text_of_the_call=analyzer.return_the_code_of_the_call_that_starts_at(position);
			int line_number=analyzer.return_the_line_number_of_the_position(position);

			if (text_of_the_call.indexOf("new NativeCallback(function")<0)
			{
				this.report.add_error("the shape of an Interceptor.replace()","not a normal function",
						"The NativeCallback of an Interceptor.replace() is not a normal function, so frida cannot bind the invocation context to it and this.context is undefined inside it",
						analyzer.return_the_line_at_the_position(position),line_number);
			}
			if (text_of_the_call.indexOf("args[")>=0)
			{
				this.report.add_error("the shape of an Interceptor.replace()","args in a NativeCallback",
						"The body of a NativeCallback refers to args[], which does not exist there. Its parameters are the arg_<number> of its own signature",
						analyzer.return_the_line_at_the_position(position),line_number);
			}
		}
	}

	/*
	 * The names of the Windows modules are compared without regard to the case and with the .dll suffix tolerated. That
	 * tolerance must never be applied on the other systems, where the file names are case sensitive: it would let a
	 * library match a different library whose name only differs in case.
	 */
	protected void check_that_the_windows_tolerance_is_guarded(JavascriptTextAnalyzer analyzer)
	{
		this.report.count_one_check_that_was_run();
		ArrayList<int[]> ranges_of_the_windows_branches=find_the_ranges_of_the_windows_branches(analyzer);
		ArrayList<Integer> positions_of_the_dll=analyzer.return_the_positions_anywhere_of(".dll");
		/*One line can mention the suffix three times, and reporting the same line three times says nothing more than reporting it once*/
		LinkedHashSet<Integer> lines_that_were_already_reported=new LinkedHashSet<Integer>();
		for (int i=0;i<positions_of_the_dll.size();i++)
		{
			int position=positions_of_the_dll.get(i).intValue();
			if (is_the_position_on_a_line_that_is_a_comment(analyzer,position).booleanValue())
			{
				continue;
			}
			/*
			 * Careful: what has to be guarded is the suffix being appended to a name, and not every name that happens to end in
			 * .dll . The name of the program is one such name whenever the program is a library, and so is the name of every
			 * module that the imported symbols are looked up in, and both of those are simply what the database says. The two are
			 * told apart by the character in front: the tolerance writes the extension on its own, so the quote that opens the
			 * string sits immediately before the dot, whereas a real name has its own characters there.
			 */
			if (position==0 || (analyzer.return_the_original_text().charAt(position-1)!='\'' && analyzer.return_the_original_text().charAt(position-1)!='"'))
			{
				continue;
			}
			if (lines_that_were_already_reported.contains(Integer.valueOf(analyzer.return_the_line_number_of_the_position(position))))
			{
				continue;
			}
			Boolean it_is_inside_a_windows_branch=false;
			for (int j=0;j<ranges_of_the_windows_branches.size();j++)
			{
				int[] range=ranges_of_the_windows_branches.get(j);
				if (position>=range[0] && position<=range[1])
				{
					it_is_inside_a_windows_branch=true;
				}
			}
			if (!it_is_inside_a_windows_branch.booleanValue())
			{
				lines_that_were_already_reported.add(Integer.valueOf(analyzer.return_the_line_number_of_the_position(position)));
				this.report.add_warning("the .dll tolerance is not guarded","unguarded dll",
						"The script mentions .dll outside of a check on Process.platform, so the tolerance that only Windows needs would be applied everywhere",
						"",analyzer.return_the_line_number_of_the_position(position))
						.with("every mention of .dll is inside a block that follows a check on Process.platform","yes","no, this one is not")
						.with_the_context("the line of the script that mentions it",analyzer.return_the_line_at_the_position(position));
			}
		}
	}

	protected ArrayList<int[]> find_the_ranges_of_the_windows_branches(JavascriptTextAnalyzer analyzer)
	{
		ArrayList<int[]> retval=new ArrayList<int[]>();
		String code=analyzer.return_the_code_only_text();
		/*The comparison itself has its string blanked out, so what is left in the code is Process.platform=== followed by spaces*/
		ArrayList<Integer> positions=analyzer.return_the_positions_in_the_code_of("Process.platform");
		for (int i=0;i<positions.size();i++)
		{
			int position=positions.get(i).intValue();
			int position_of_the_open_brace=code.indexOf("{",position);
			if (position_of_the_open_brace<0)
			{
				continue;
			}
			int position_of_the_close_brace=analyzer.return_the_position_that_closes(position_of_the_open_brace,'{','}');
			if (position_of_the_close_brace<0)
			{
				continue;
			}
			int[] range={position,position_of_the_close_brace};
			retval.add(range);
		}
		return retval;
	}

	protected Boolean is_the_position_on_a_line_that_is_a_comment(JavascriptTextAnalyzer analyzer,int position)
	{
		String line=analyzer.return_the_line_at_the_position(position);
		return Boolean.valueOf(line.startsWith("//") || line.startsWith("*") || line.startsWith("/*"));
	}

	/*The helper that compares the names of the modules is declared at most once, and never used without being declared*/
	protected void check_the_module_name_helper(JavascriptTextAnalyzer analyzer)
	{
		this.report.count_one_check_that_was_run();
		int how_many_times_declared=analyzer.return_how_many_times_in_the_code("function does_module_name_match_the_wanted_one_");
		int how_many_times_used=analyzer.return_how_many_times_in_the_code("does_module_name_match_the_wanted_one_")-how_many_times_declared;
		if (how_many_times_declared>1)
		{
			this.report.add_error("the helper that compares module names","declared more than once",
					"The function that compares the names of the modules is declared "+how_many_times_declared+" times in the same script",
					"a script must declare it at most once",0);
		}
		if (how_many_times_used>0 && how_many_times_declared==0)
		{
			this.report.add_error("the helper that compares module names","used without being declared",
					"The script calls the function that compares the names of the modules, but never declares it",
					"the prologue that uses it has to emit it as well",0);
		}
	}

	/*A script that carries a prologue has to close it, and it registers the interceptors exactly once*/
	protected void check_the_prologue_and_the_epilogue(JavascriptTextAnalyzer analyzer,Expectations expectations)
	{
		this.report.count_one_check_that_was_run();
		int how_many_flushes=analyzer.return_how_many_times_in_the_code("Interceptor.flush()");
		if (expectations.the_script_has_a_prologue.booleanValue())
		{
			if (how_many_flushes!=1)
			{
				this.report.add_error("the shape of the script","flush count",
						"A generated script has to flush the interceptors exactly once, this one does it "+how_many_flushes+" times",
						"",0);
			}
			if (analyzer.return_how_many_times_in_the_code("var module_name_"+this.sanitized_name_of_the_program)==0)
			{
				this.report.add_error("the shape of the script","module name not declared",
						"The script never declares the variable that holds the name of the module",
						"expected a declaration of module_name_"+this.sanitized_name_of_the_program,0);
			}
		}
		else
		{
			if (analyzer.return_how_many_times_in_the_code("function start_timer_for_intercept")>0)
			{
				this.report.add_error("the shape of the snippet","prologue in a snippet",
						"A snippet was asked for, but the output carries the prologue of a whole script",
						"",0);
			}
		}
	}

	/*----------------------------------------------------------------------------------------------------------------
	 * checks that ask the database
	 *--------------------------------------------------------------------------------------------------------------*/

	/*
	 * Every offset that the script computes is turned back into an address and looked up in the database. The plugin only
	 * ever hooks the first byte of an instruction, so anything else means the generated script hooks something that is not
	 * there. When the hook is named after a function, the name is compared with the one the database has.
	 */
	protected void check_the_hooked_addresses_against_the_database(JavascriptTextAnalyzer analyzer,Expectations expectations)
	{
		this.report.count_one_check_that_was_run();
		Listing listing=this.current_program.getListing();
		Address image_base=this.current_program.getImageBase();
		String code=analyzer.return_the_code_only_text();

		ArrayList<Integer> positions=analyzer.return_the_positions_in_the_code_of("var offset_of_");
		int how_many_addresses_were_checked=0;
		for (int i=0;i<positions.size();i++)
		{
			int position=positions.get(i).intValue();
			int position_of_the_name=position+"var offset_of_".length();
			int j=position_of_the_name;
			while (j<code.length() && JavascriptTextAnalyzer.is_a_character_that_can_be_inside_a_name(code.charAt(j)).booleanValue())
			{
				j++;
			}
			String name_of_the_hook=code.substring(position_of_the_name,j);
			/*What follows is "=0x<hex>;"*/
			int position_of_the_0x=code.indexOf("0x",j);
			if (position_of_the_0x<0)
			{
				continue;
			}
			int k=position_of_the_0x+2;
			int start_of_the_digits=k;
			while (k<code.length() && is_a_hexadecimal_digit(code.charAt(k)).booleanValue())
			{
				k++;
			}
			String hexadecimal_of_the_offset=code.substring(start_of_the_digits,k);
			if (hexadecimal_of_the_offset.equals(""))
			{
				continue;
			}
			long value_of_the_offset;
			try {
				value_of_the_offset=Long.parseLong(hexadecimal_of_the_offset,16);
			}
			catch (NumberFormatException ex)
			{
				this.report.add_error("an offset that cannot be read","unparseable offset",
						"An offset of the script cannot be read as a number",
						analyzer.return_the_line_at_the_position(position),
						analyzer.return_the_line_number_of_the_position(position));
				continue;
			}

			/*The operation that is applied on the base of the module tells whether the offset is added or subtracted*/
			Boolean the_offset_is_subtracted=false;
			int position_of_the_use=code.indexOf("offset_of_"+name_of_the_hook,k);
			if (position_of_the_use>=0)
			{
				int start_of_the_neighbourhood=Math.max(0,position_of_the_use-40);
				String text_before_the_use=code.substring(start_of_the_neighbourhood,position_of_the_use);
				if (text_before_the_use.indexOf(".sub(")>=0)
				{
					the_offset_is_subtracted=true;
				}
			}

			Address address_of_the_hook=null;
			try {
				if (the_offset_is_subtracted.booleanValue())
				{
					address_of_the_hook=image_base.subtract(value_of_the_offset);
				}
				else
				{
					address_of_the_hook=image_base.add(value_of_the_offset);
				}
			}
			catch (Exception ex)
			{
				this.report.add_error("an offset that does not lead anywhere","offset outside the program",
						"The offset of the hook '"+name_of_the_hook+"' does not land on any address of the program",
						"offset 0x"+hexadecimal_of_the_offset+(the_offset_is_subtracted.booleanValue()?" subtracted from":" added to")+" the image base "+image_base,
						analyzer.return_the_line_number_of_the_position(position));
				continue;
			}

			how_many_addresses_were_checked++;

			Instruction instruction_at_the_address=listing.getInstructionAt(address_of_the_hook);
			if (instruction_at_the_address==null)
			{
				this.report.add_error("a hook on something that is not an instruction","not an instruction",
						"The script hooks an address at which the database has no instruction",
						"hook '"+name_of_the_hook+"' resolves to "+address_of_the_hook,
						analyzer.return_the_line_number_of_the_position(position));
				continue;
			}

			/*When the hook is named after a function, the database has to agree that the function is there and is that one*/
			Function function_at_the_address=this.current_program.getFunctionManager().getFunctionAt(address_of_the_hook);
			if (function_at_the_address!=null)
			{
				String sanitized_name_of_the_function=function_at_the_address.getName(true).replaceAll("[^"+this.characters_allowed_in_variable_name+"]","_");
				if (name_of_the_hook.startsWith(sanitized_name_of_the_function+"_"))
				{
					continue;	//the name of the hook agrees with the database
				}
			}
		}

		this.report.add_info("addresses checked against the database","how many",
				"Turned "+how_many_addresses_were_checked+" offsets of the script back into addresses and looked every one of them up",
				"");
	}

	/*An address that the caller explicitly asked to be hooked has to be in the script*/
	protected void check_that_the_requested_addresses_are_there(JavascriptTextAnalyzer analyzer,Expectations expectations)
	{
		if (expectations.addresses_that_must_be_hooked.size()==0)
		{
			return;
		}
		this.report.count_one_check_that_was_run();
		Address image_base=this.current_program.getImageBase();
		String code=analyzer.return_the_code_only_text();
		for (int i=0;i<expectations.addresses_that_must_be_hooked.size();i++)
		{
			Address address_that_must_be_hooked=expectations.addresses_that_must_be_hooked.get(i);
			long offset=address_that_must_be_hooked.getOffset()-image_base.getOffset();
			String hexadecimal_of_the_offset="0x"+Long.toHexString(offset<0?-offset:offset);
			if (code.indexOf("="+hexadecimal_of_the_offset+";")<0 && code.indexOf("("+hexadecimal_of_the_offset+")")<0)
			{
				this.report.add_error("an address that was asked for is missing","missing requested address",
						"The address "+address_that_must_be_hooked+" was asked for, but its offset "+hexadecimal_of_the_offset+" is nowhere in the script",
						"",0);
			}
		}
	}

	/*Every function whose name matches the regular expression that was asked for has to be in the script*/
	protected void check_that_the_requested_functions_are_there(JavascriptTextAnalyzer analyzer,Expectations expectations)
	{
		if (expectations.regex_of_function_names_that_must_be_hooked.equals(""))
		{
			return;
		}
		this.report.count_one_check_that_was_run();
		Pattern pattern;
		try {
			pattern=Pattern.compile(expectations.regex_of_function_names_that_must_be_hooked,Pattern.CASE_INSENSITIVE);
		}
		catch (Exception ex)
		{
			return;	//the regular expression of the test itself is wrong, that is not a finding about the plugin
		}
		String code=analyzer.return_the_code_only_text();
		Address image_base=this.current_program.getImageBase();
		FunctionIterator function_iterator=this.current_program.getListing().getFunctions(true);
		int how_many_were_expected=0;
		while (function_iterator!=null && function_iterator.hasNext())
		{
			Function function=function_iterator.next();
			String name_of_the_function=function.getName(true).replace("\"","_");
			if (!pattern.matcher(name_of_the_function).matches())
			{
				continue;
			}
			how_many_were_expected++;
			long offset=function.getEntryPoint().getOffset()-image_base.getOffset();
			String hexadecimal_of_the_offset="0x"+Long.toHexString(offset<0?-offset:offset);
			if (code.indexOf("="+hexadecimal_of_the_offset+";")<0)
			{
				this.report.add_error("a function that the regular expression matched is missing","missing matched function",
						"The function "+name_of_the_function+" matches the regular expression that was asked for, but it is not hooked",
						"expected the offset "+hexadecimal_of_the_offset+" of "+function.getEntryPoint(),0);
			}
		}
		this.report.add_info("functions matched by the regular expression","how many",
				how_many_were_expected+" functions of the program match the regular expression that was asked for","");
	}

	/*Every exported entry point has to be in the script when the option that hooks them was on*/
	protected void check_that_the_exported_entry_points_are_there(JavascriptTextAnalyzer analyzer,Expectations expectations)
	{
		if (!expectations.every_exported_entry_point_must_be_hooked.booleanValue())
		{
			return;
		}
		this.report.count_one_check_that_was_run();
		String code=analyzer.return_the_code_only_text();
		Address image_base=this.current_program.getImageBase();
		Listing listing=this.current_program.getListing();
		SymbolTable symbol_table=this.current_program.getSymbolTable();
		AddressIterator address_iterator=symbol_table.getExternalEntryPointIterator();
		int how_many_were_expected=0;
		while (address_iterator!=null && address_iterator.hasNext())
		{
			Address address_of_the_entry_point=address_iterator.next();
			/*The plugin can only hook an entry point that is the first byte of an instruction, the others are reported by it as comments*/
			if (listing.getInstructionAt(address_of_the_entry_point)==null)
			{
				continue;
			}
			how_many_were_expected++;
			long offset=address_of_the_entry_point.getOffset()-image_base.getOffset();
			String hexadecimal_of_the_offset="0x"+Long.toHexString(offset<0?-offset:offset);
			if (code.indexOf("="+hexadecimal_of_the_offset+";")<0)
			{
				this.report.add_error("an exported entry point is missing","missing entry point",
						"The exported entry point "+address_of_the_entry_point+" is an instruction but it is not hooked",
						"expected the offset "+hexadecimal_of_the_offset,0);
			}
		}
		this.report.add_info("exported entry points","how many",
				how_many_were_expected+" exported entry points of the program are instructions and were expected in the script","");
	}

	protected void check_the_custom_text(JavascriptTextAnalyzer analyzer,Expectations expectations)
	{
		/*A text that the user asked to be placed inside the hooks cannot be anywhere when the script installs no hook at all*/
		if (analyzer.return_how_many_times_in_the_code("var offset_of_")==0)
		{
			return;
		}
		if (expectations.text_that_must_appear_somewhere.equals(""))
		{
			return;
		}
		this.report.count_one_check_that_was_run();
		if (analyzer.return_the_original_text().indexOf(expectations.text_that_must_appear_somewhere)<0)
		{
			this.report.add_error("text that was asked for is missing","missing custom text",
					"A piece of text that was asked to be included is nowhere in the script",
					"expected to find: "+expectations.text_that_must_appear_somewhere,0);
		}
	}
}
