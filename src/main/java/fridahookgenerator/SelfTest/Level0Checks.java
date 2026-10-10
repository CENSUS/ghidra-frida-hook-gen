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

import fridahookgenerator.ChatGPTAPICaller;
import fridahookgenerator.FridaAbiHandler;
import fridahookgenerator.HookGeneratorUtils;
import fridahookgenerator.ParserOfComputedCalls;
import fridahookgenerator.ParsersOfComputedCalls.ARM32ParserOfComputedCall;
import fridahookgenerator.ParsersOfComputedCalls.ARM64ParserOfComputedCall;
import fridahookgenerator.ParsersOfComputedCalls.X86ParserOfComputedCall;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/*
 * The checks that do not need a generated script: they call a piece of the plugin directly, with a known input, and
 * compare what comes out with what was expected.
 *
 * Everything here goes through the public methods of the plugin only, so that this whole directory can be deleted without
 * anything else having to be changed.
 *
 * Careful: the parsers of the computed calls decide what they are parsing from the language of the program that they are
 * given, so the cases for an architecture can only be run when the program that is loaded is of that architecture. The
 * cases for the others are reported as skipped instead of being silently dropped.
 */
public class Level0Checks {

	protected Program current_program;
	protected SelfTestReport report;
	protected String name_of_the_module_variable="module_name_TEST";

	public Level0Checks(Program current_program,SelfTestReport report)
	{
		this.current_program=current_program;
		this.report=report;
	}

	public void run_all_the_level0_checks()
	{
		this.report.set_the_current_combination("level 0");
		check_the_helpers_that_turn_an_offset_into_code();
		check_the_escaping_of_a_string_literal();
		check_the_sanitizing_of_the_names();
		check_the_abi_of_a_replacement();
		check_where_the_arguments_of_an_attach_hook_are_read_from();
		check_the_reader_of_the_replies_of_the_api();
		check_the_parsers_of_the_computed_calls();
		this.report.set_the_current_combination("");
	}

	/*----------------------------------------------------------------------------------------------------------------*/

	protected void check_the_helpers_that_turn_an_offset_into_code()
	{
		String name_of_check="the sign of an offset";
		int how_many_errors_before=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR);

		expect_the_same(name_of_check,"operation of a positive offset","add",HookGeneratorUtils.return_frida_operation_for_offset(0x1000L));
		expect_the_same(name_of_check,"operation of a zero offset","add",HookGeneratorUtils.return_frida_operation_for_offset(0L));
		expect_the_same(name_of_check,"operation of a negative offset","sub",HookGeneratorUtils.return_frida_operation_for_offset(-0x1000L));
		expect_the_same(name_of_check,"hexadecimal of a positive offset","0x1000",HookGeneratorUtils.return_hex_str_for_absolute_value_of_offset(0x1000L));
		expect_the_same(name_of_check,"hexadecimal of a zero offset","0x0",HookGeneratorUtils.return_hex_str_for_absolute_value_of_offset(0L));
		/*This is the one that matters: a negative offset must never come out as the unsigned rendering of the same number*/
		expect_the_same(name_of_check,"hexadecimal of a negative offset","0x1000",HookGeneratorUtils.return_hex_str_for_absolute_value_of_offset(-0x1000L));

		int how_many_errors=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR)-how_many_errors_before;
		this.report.add_summary_of_a_step("level 0: the sign of an offset",how_many_errors,0,"6 cases");
	}

	/*
	 * The abi that an Interceptor.replace() hook is given, worked out from the calling convention that the database has.
	 *
	 * Nearly every case below expects an empty answer, and that is the point of the table rather than a gap in it. Frida accepts
	 * nine abis and only the ones of 32 bit x86 are ever a choice, so everywhere else the right thing to write is nothing and let
	 * frida use the abi of the system.
	 *
	 * The cases that matter most are the ones where Ghidra says __stdcall and the answer is still nothing: on 64 bit Windows the
	 * compiler spec declares __stdcall, __cdecl and __fastcall as aliases of one another, all naming the single convention that
	 * the platform has, so believing the name there would write stdcall for a function that is nothing of the sort.
	 */
	protected void check_the_abi_of_a_replacement()
	{
		String name_of_check="level 0: the abi of a replacement";
		int how_many_errors_before=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR);
		int how_many_checks_before=this.report.return_how_many_checks_were_run();

		/*The three that are a real choice, and only on 32 bit x86 built by Visual Studio*/
		expect_the_same(name_of_check,"a stdcall function of 32 bit Windows","stdcall",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("__stdcall","x86:LE:32:default","windows"));
		expect_the_same(name_of_check,"a fastcall function of 32 bit Windows","fastcall",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("__fastcall","x86:LE:32:default","windows"));
		expect_the_same(name_of_check,"a method of a class of 32 bit Windows","thiscall",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("__thiscall","x86:LE:32:default","windows"));

		/*The one that is the default there, so writing it would only make every hook longer*/
		expect_the_same(name_of_check,"a cdecl function of 32 bit Windows, which is what frida uses anyway","",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("__cdecl","x86:LE:32:default","windows"));

		/*The name is reused by Ghidra for the one convention that these platforms have*/
		expect_the_same(name_of_check,"the same name on 64 bit Windows, where it means the convention of the platform","",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("__stdcall","x86:LE:64:default","windows"));
		expect_the_same(name_of_check,"the same name on AArch64, which has one calling convention","",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("__stdcall","AARCH64:LE:64:v8A","windows"));
		expect_the_same(name_of_check,"the same name on 32 bit ARM","",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("__stdcall","ARM:LE:32:v8","default"));

		/*The right width, but a compiler that does not mean the same thing by the name*/
		expect_the_same(name_of_check,"a stdcall of gcc on 32 bit, which frida does not offer outside Windows","",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("__stdcall","x86:LE:32:default","gcc"));
		expect_the_same(name_of_check,"a fastcall of Borland, which is not the fastcall of Visual Studio","",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("__fastcall","x86:LE:32:default","borlandcpp"));

		/*Names that frida has no abi for, and names that say nothing*/
		expect_the_same(name_of_check,"a convention that frida has no name for","",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("__vectorcall","x86:LE:32:default","windows"));
		expect_the_same(name_of_check,"a function whose convention the database does not know","",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("unknown","x86:LE:32:default","windows"));
		expect_the_same(name_of_check,"a function that carries the default of its compiler spec","",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("default","x86:LE:32:default","windows"));
		expect_the_same(name_of_check,"nothing at all","",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention(null,"x86:LE:32:default","windows"));
		expect_the_same(name_of_check,"a convention with no language to read it against","",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("__stdcall",null,"windows"));

		/*
		 * And what the hook says when no abi is written into it. An empty abi has three causes that need three different answers,
		 * and the one that matters is the third: there the replacement is installed with the abi of the system although the
		 * convention is not that one, so the generated code may be wrong rather than merely unspecific.
		 */
		expect_the_same(name_of_check,"nothing is said when an abi is written","",
				FridaAbiHandler.return_the_reason_why_no_abi_is_written("__thiscall","x86:LE:32:default","windows"));
		expect_the_same(name_of_check,"nothing is said for cdecl, which is the abi frida uses anyway","",
				FridaAbiHandler.return_the_reason_why_no_abi_is_written("__cdecl","x86:LE:32:default","windows"));
		expect_the_same(name_of_check,"a function with no convention is told where conventions come from","yes",
				FridaAbiHandler.return_the_reason_why_no_abi_is_written("unknown","x86:LE:32:default","windows").indexOf("Decompiler Parameter ID")>=0?"yes":"no");
		expect_the_same(name_of_check,"a function with no convention at all is treated the same way","yes",
				FridaAbiHandler.return_the_reason_why_no_abi_is_written(null,"x86:LE:32:default","windows").indexOf("Decompiler Parameter ID")>=0?"yes":"no");
		expect_the_same(name_of_check,"a convention frida cannot express is reported as a risk","yes",
				FridaAbiHandler.return_the_reason_why_no_abi_is_written("__vectorcall","x86:LE:32:default","windows").indexOf("read from the wrong place")>=0?"yes":"no");
		expect_the_same(name_of_check,"and it is reported even where no abi could have been chosen","yes",
				FridaAbiHandler.return_the_reason_why_no_abi_is_written("__vectorcall","x86:LE:64:default","windows").indexOf("read from the wrong place")>=0?"yes":"no");
		expect_the_same(name_of_check,"a name that is an alias of the one convention of 64 bit Windows says nothing","",
				FridaAbiHandler.return_the_reason_why_no_abi_is_written("__stdcall","x86:LE:64:default","windows"));
		expect_the_same(name_of_check,"the name of the default model of 32 bit Linux says nothing","",
				FridaAbiHandler.return_the_reason_why_no_abi_is_written("__stdcall","x86:LE:32:default","gcc"));
		expect_the_same(name_of_check,"a target with one calling convention says nothing","",
				FridaAbiHandler.return_the_reason_why_no_abi_is_written("unknown","AARCH64:LE:64:v8A","default"));

		/*
		 * And what an Interceptor.attach() hook is told about its own arguments. That form takes no abi at all, so where the
		 * convention passes arguments in registers the args[] of the hook are not the arguments of the function and the only thing
		 * that can be done is to say which register to read instead.
		 *
		 * Careful with __stdcall: it passes everything on the stack exactly as __cdecl does and only differs in who cleans up
		 * afterwards, which does not concern a hook that watches the call, so it must stay silent.
		 */
		expect_the_same(name_of_check,"an attach hook on a thiscall function is told about ECX","yes",
				FridaAbiHandler.return_the_warning_about_the_arguments_of_an_attach_hook("__thiscall","x86:LE:32:default","windows").indexOf("this.context.ecx")>=0?"yes":"no");
		expect_the_same(name_of_check,"an attach hook on a fastcall function is told about EDX as well","yes",
				FridaAbiHandler.return_the_warning_about_the_arguments_of_an_attach_hook("__fastcall","x86:LE:32:default","windows").indexOf("this.context.edx")>=0?"yes":"no");
		expect_the_same(name_of_check,"an attach hook on a stdcall function is told nothing, its arguments are on the stack","",
				FridaAbiHandler.return_the_warning_about_the_arguments_of_an_attach_hook("__stdcall","x86:LE:32:default","windows"));
		expect_the_same(name_of_check,"an attach hook on a cdecl function is told nothing","",
				FridaAbiHandler.return_the_warning_about_the_arguments_of_an_attach_hook("__cdecl","x86:LE:32:default","windows"));
		expect_the_same(name_of_check,"and nothing is said on a target where the names mean the one convention of the platform","",
				FridaAbiHandler.return_the_warning_about_the_arguments_of_an_attach_hook("__thiscall","x86:LE:64:default","windows"));
		expect_the_same(name_of_check,"a function with no convention is told nothing about its arguments","",
				FridaAbiHandler.return_the_warning_about_the_arguments_of_an_attach_hook(null,"x86:LE:32:default","windows"));

		/*
		 * The name of the convention comes out of the compiler spec of the database and is written into a comment that begins with
		 * // . A name carrying a carriage return or a line feed would end that comment where it sits and leave the rest of the
		 * sentence behind as javascript, which is how a name in a database becomes code in a script.
		 *
		 * Careful: javascript ends a line at four characters and not at two. A carriage return does it as a line feed does, and so
		 * do the line separator and the paragraph separator, which are neither of them control characters and would survive an
		 * escaper that only looks for those. Anything that is not a letter, a digit or an underscore is therefore taken out of the
		 * name, and nothing is lost by that: every convention that Ghidra ships is written with those alone, so a name that needs
		 * repairing is a name worth distrusting anyway.
		 */
		String the_line_separator_of_javascript=String.valueOf((char)0x2028);
		String the_paragraph_separator_of_javascript=String.valueOf((char)0x2029);
		String[] the_names_that_must_not_break_a_comment={"__odd\ncall","__odd\rcall","a"+the_line_separator_of_javascript+"b",
				"a"+the_paragraph_separator_of_javascript+"b","__odd*/call","__odd\"call","__odd'call","__odd\\call"};
		for (int i=0;i<the_names_that_must_not_break_a_comment.length;i++)
		{
			String what_is_written=FridaAbiHandler.return_the_reason_why_no_abi_is_written(
					the_names_that_must_not_break_a_comment[i],"x86:LE:32:default","windows");
			expect_the_same(name_of_check,"a convention whose name could end the comment it is written into, case "+i,"no",
					(what_is_written.indexOf("\n")>=0 || what_is_written.indexOf("\r")>=0
							|| what_is_written.indexOf(the_line_separator_of_javascript)>=0
							|| what_is_written.indexOf(the_paragraph_separator_of_javascript)>=0)?"yes":"no");
			String what_the_note_says=FridaAbiHandler.return_the_note_that_says_that_the_parameters_are_read_from_their_storage(
					the_names_that_must_not_break_a_comment[i],new String[]{"this.context.ecx"},"x86:LE:32:default","windows");
			expect_the_same(name_of_check,"and the same name written into the note, case "+i,"no",
					(what_the_note_says.indexOf("\n")>=0 || what_the_note_says.indexOf("\r")>=0
							|| what_the_note_says.indexOf(the_line_separator_of_javascript)>=0
							|| what_the_note_says.indexOf(the_paragraph_separator_of_javascript)>=0)?"yes":"no");
		}
		expect_the_same(name_of_check,"a name that needs nothing done to it is written as it is","__vectorcall",
				FridaAbiHandler.return_the_name_of_a_calling_convention_made_safe_for_a_comment("__vectorcall"));
		expect_the_same(name_of_check,"a name with a line feed in it cannot carry it through","__odd_call",
				FridaAbiHandler.return_the_name_of_a_calling_convention_made_safe_for_a_comment("__odd\ncall"));
		expect_the_same(name_of_check,"no name at all is no name","",
				FridaAbiHandler.return_the_name_of_a_calling_convention_made_safe_for_a_comment(null));

		/*
		 * And the promise that the whole table rests on: whatever the database calls a convention, the answer is either nothing at
		 * all or one of the nine words frida accepts. A word that frida does not know would be passed to NativeFunction and throw at
		 * the moment the script is loaded, taking every hook after it with it.
		 */
		/*Read from the one place the words are written down, so that this check and the one that refuses an abi cannot come to disagree*/
		String[] the_abis_that_frida_accepts=OptionSpecificChecks.the_abis_that_frida_accepts;
		String[] the_names_a_database_may_hold={"__stdcall","__cdecl","__fastcall","__thiscall","__vectorcall","__regcall","__pascal",
				"syscall","processEntry","unknown","default","","__stdcall ","  __thiscall","THISCALL","__thiscall__","std"};
		for (int i=0;i<the_names_a_database_may_hold.length;i++)
		{
			String what_came_out=FridaAbiHandler.return_frida_abi_for_the_calling_convention(the_names_a_database_may_hold[i],"x86:LE:32:default","windows");
			boolean it_is_one_that_frida_knows=what_came_out.equals("");
			for (int j=0;j<the_abis_that_frida_accepts.length;j++)
			{
				if (what_came_out.equals(the_abis_that_frida_accepts[j]))
				{
					it_is_one_that_frida_knows=true;
				}
			}
			expect_the_same(name_of_check,"the abi for the name '"+the_names_a_database_may_hold[i]+"' is one frida accepts, or none","yes",
					it_is_one_that_frida_knows?"yes":"no");
			/*
			 * And the pair that the replacement is built out of: the abi and the line that explains why there is none. A hook that
			 * carried both would hand frida an abi and tell its reader in the same breath that none was written, and the two are
			 * decided by the same question, so one of them has to be empty whatever the name is.
			 */
			String what_is_explained=FridaAbiHandler.return_the_reason_why_no_abi_is_written(
					the_names_a_database_may_hold[i],"x86:LE:32:default","windows");
			expect_the_same(name_of_check,"the name '"+the_names_a_database_may_hold[i]+"' is never given an abi and an excuse for having none","no",
					(!what_came_out.equals("") && !what_is_explained.equals(""))?"yes":"no");
		}
		/*
		 * Careful with two of the names above. A name that is spelled with capitals is a different name and must not be mapped, and a
		 * name with spaces around it is the same name and must be, because a convention arrives from the database as it was typed
		 * into a compiler spec.
		 */
		expect_the_same(name_of_check,"a name that differs only in its capitals is not the same name","",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("THISCALL","x86:LE:32:default","windows"));
		expect_the_same(name_of_check,"a name with spaces around it is the same name","thiscall",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("  __thiscall  ","x86:LE:32:default","windows"));
		expect_the_same(name_of_check,"a name that merely begins like one of them is not one of them","",
				FridaAbiHandler.return_frida_abi_for_the_calling_convention("__thiscall__","x86:LE:32:default","windows"));

		/*
		 * And the seam the generator calls across. It hands over the function and the program rather than the text of their names,
		 * so what has to hold here is that nothing it could hand over makes any of this throw: a generator that asked for an abi
		 * while a program was being closed under it would otherwise take the whole batch of hooks down with it.
		 */
		expect_the_same(name_of_check,"no program at all has no language","",
				FridaAbiHandler.return_the_identifier_of_the_language_of(null));
		expect_the_same(name_of_check,"no program at all has no compiler spec","",
				FridaAbiHandler.return_the_identifier_of_the_compiler_spec_of(null));
		expect_the_same(name_of_check,"and no abi can be chosen for it","no",
				FridaAbiHandler.can_an_abi_be_chosen_for_this_target((Program)null).booleanValue()?"yes":"no");
		expect_the_same(name_of_check,"no function means no abi is written into a replacement","",
				FridaAbiHandler.return_the_text_of_the_abi_for_a_replacement(null,Boolean.TRUE,this.current_program));
		expect_the_same(name_of_check,"no function means nothing is said about the abi of a replacement","",
				FridaAbiHandler.return_the_comment_about_the_abi_of_a_replacement(null,Boolean.TRUE,this.current_program));
		expect_the_same(name_of_check,"an option that was never answered writes no abi","",
				FridaAbiHandler.return_the_text_of_the_abi_for_a_replacement(null,null,this.current_program));

		int how_many_errors=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR)-how_many_errors_before;
		this.report.add_summary_of_a_step(name_of_check,how_many_errors,0,
				(this.report.return_how_many_checks_were_run()-how_many_checks_before)+" cases");
	}

	/*
	 * Where an Interceptor.attach() hook reads each of its arguments from.
	 *
	 * That form of hook takes no abi, and the args[] of frida on 32 bit x86 are the stack and nothing else. A convention that puts
	 * the first arguments in registers therefore leaves every argument after them at an index of args[] smaller than its own
	 * position, so a hook that prints args[0], args[1], ... for such a function prints the second argument under the name of the
	 * first and reads one slot past the end for the last.
	 *
	 * The pieces below are the ones that decide the text. The case that matters most is the last group: for a convention that puts
	 * everything on the stack the answer has to come out as the very args[<position>] that this plugin has always written, or
	 * switching the option on would change hooks it has no business changing.
	 */
	protected void check_where_the_arguments_of_an_attach_hook_are_read_from()
	{
		String name_of_check="level 0: where the arguments of an attach hook are read from";
		int how_many_errors_before=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR);
		int how_many_checks_before=this.report.return_how_many_checks_were_run();

		/*The registers that the context of frida carries for a 32 bit x86 process. The name arrives from the database in capitals*/
		expect_the_same(name_of_check,"the register of the first argument of a thiscall","this.context.ecx",
				FridaAbiHandler.return_the_javascript_that_reads_a_register_of_a_32_bit_x86_process("ECX"));
		expect_the_same(name_of_check,"the same name already in lowercase","this.context.ecx",
				FridaAbiHandler.return_the_javascript_that_reads_a_register_of_a_32_bit_x86_process("ecx"));
		expect_the_same(name_of_check,"the register of the second argument of a fastcall","this.context.edx",
				FridaAbiHandler.return_the_javascript_that_reads_a_register_of_a_32_bit_x86_process("EDX"));
		expect_the_same(name_of_check,"a name with spaces around it","this.context.ebx",
				FridaAbiHandler.return_the_javascript_that_reads_a_register_of_a_32_bit_x86_process("  EBX  "));
		/*
		 * The narrow names. A parameter of one or two bytes is given the name of the part of the register that holds it, and the
		 * context of frida carries only the whole register, so the whole one is what is read: the value is in its lowest bytes.
		 */
		expect_the_same(name_of_check,"a one byte parameter in the low byte of ECX","this.context.ecx",
				FridaAbiHandler.return_the_javascript_that_reads_a_register_of_a_32_bit_x86_process("CL"));
		expect_the_same(name_of_check,"a two byte parameter in the low half of ECX","this.context.ecx",
				FridaAbiHandler.return_the_javascript_that_reads_a_register_of_a_32_bit_x86_process("CX"));
		expect_the_same(name_of_check,"and the same for the second register of a fastcall","this.context.edx",
				FridaAbiHandler.return_the_javascript_that_reads_a_register_of_a_32_bit_x86_process("DL"));
		/*
		 * And the one that must not be read as a whole register, however tempting the parent of it looks. A parameter in AH sits in
		 * the second byte of EAX, so printing EAX would print a different byte, and refusing it here is what makes the whole
		 * function fall back to the args[] it always used and say so.
		 */
		expect_the_same(name_of_check,"a parameter in a high byte, which is not at the bottom of its register","",
				FridaAbiHandler.return_the_javascript_that_reads_a_register_of_a_32_bit_x86_process("AH"));
		expect_the_same(name_of_check,"and neither is the high byte of ECX","",
				FridaAbiHandler.return_the_javascript_that_reads_a_register_of_a_32_bit_x86_process("CH"));
		expect_the_same(name_of_check,"a register of a 64 bit process","",
				FridaAbiHandler.return_the_javascript_that_reads_a_register_of_a_32_bit_x86_process("RCX"));
		expect_the_same(name_of_check,"a register that carries floating point arguments","",
				FridaAbiHandler.return_the_javascript_that_reads_a_register_of_a_32_bit_x86_process("XMM0"));
		expect_the_same(name_of_check,"no register at all","",
				FridaAbiHandler.return_the_javascript_that_reads_a_register_of_a_32_bit_x86_process(null));
		expect_the_same(name_of_check,"an empty name","",
				FridaAbiHandler.return_the_javascript_that_reads_a_register_of_a_32_bit_x86_process(""));

		/*The stack. The return address sits at offset 0 and the first argument right after it, which frida calls args[0]*/
		expect_the_same(name_of_check,"the first argument on the stack","0",
				String.valueOf(FridaAbiHandler.return_the_index_of_the_argument_of_frida_for_a_stack_offset(4)));
		expect_the_same(name_of_check,"the second argument on the stack","1",
				String.valueOf(FridaAbiHandler.return_the_index_of_the_argument_of_frida_for_a_stack_offset(8)));
		expect_the_same(name_of_check,"an argument further down the stack","10",
				String.valueOf(FridaAbiHandler.return_the_index_of_the_argument_of_frida_for_a_stack_offset(44)));
		expect_the_same(name_of_check,"the offset of the return address, which is no argument","-1",
				String.valueOf(FridaAbiHandler.return_the_index_of_the_argument_of_frida_for_a_stack_offset(0)));
		expect_the_same(name_of_check,"an offset above the return address, which is a local and no argument","-1",
				String.valueOf(FridaAbiHandler.return_the_index_of_the_argument_of_frida_for_a_stack_offset(-4)));
		expect_the_same(name_of_check,"an offset that is not a whole slot","-1",
				String.valueOf(FridaAbiHandler.return_the_index_of_the_argument_of_frida_for_a_stack_offset(6)));

		/*
		 * What is printed in front of a value. The first three cases are every argument of every hook that was generated before any
		 * of this existed, and they have to come out character for character as they always did.
		 */
		expect_the_same(name_of_check,"an argument read from its own position keeps the label it always had","args[0]",
				FridaAbiHandler.return_the_label_that_a_hook_prints_in_front_of_a_parameter(0,"args[0]",""));
		expect_the_same(name_of_check,"and the same with the name of the argument beside it","args[0](this.arg_param_1)",
				FridaAbiHandler.return_the_label_that_a_hook_prints_in_front_of_a_parameter(0,"args[0]","this.arg_param_1"));
		expect_the_same(name_of_check,"an argument further along that is still where its position says","args[3]",
				FridaAbiHandler.return_the_label_that_a_hook_prints_in_front_of_a_parameter(3,"args[3]",""));
		/*
		 * And the ones that would be a riddle without the number. The register is named beside it, because that is what a reader
		 * writes to in order to change the value; an index of args[] is not named, because it is a different number from the one in
		 * front of it and putting the two side by side is exactly what makes a reader count wrongly.
		 *
		 * Careful: how many arguments a convention keeps out of args[] is not the same for all of them, so every case below says
		 * which convention it belongs to. A thiscall passes one argument in a register, so its SECOND argument is the first thing on
		 * the stack and frida calls that args[0]. A fastcall passes two, so args[0] is its THIRD argument. Nothing in this file
		 * counts registers to work that out: it reads where the database placed each parameter, and the cases below are what the
		 * two conventions really produce, written out separately so that neither can be mistaken for the other.
		 */
		/*A thiscall of two arguments: ECX, and then the stack*/
		expect_the_same(name_of_check,"a thiscall: the first argument, which is the one in ECX","arg_0(ecx)",
				FridaAbiHandler.return_the_label_that_a_hook_prints_in_front_of_a_parameter(0,"this.context.ecx",""));
		expect_the_same(name_of_check,"a thiscall: the second argument, which is the first thing on the stack and is frida's args[0]","arg_1",
				FridaAbiHandler.return_the_label_that_a_hook_prints_in_front_of_a_parameter(1,"args[0]",""));
		expect_the_same(name_of_check,"a thiscall: the first argument with its name beside the register","arg_0(ecx, this.arg_this)",
				FridaAbiHandler.return_the_label_that_a_hook_prints_in_front_of_a_parameter(0,"this.context.ecx","this.arg_this"));
		expect_the_same(name_of_check,"a thiscall: the second argument with its name and no register to name","arg_1(this.arg_param_1)",
				FridaAbiHandler.return_the_label_that_a_hook_prints_in_front_of_a_parameter(1,"args[0]","this.arg_param_1"));
		/*
		 * And a fastcall of three arguments: ECX, EDX, and then the stack. The one on the stack is the THIRD argument of the
		 * function, so args[0] is arg_2 here and not arg_1, which is the case this whole table exists to keep straight.
		 */
		expect_the_same(name_of_check,"a fastcall: the first argument, which is the one in ECX","arg_0(ecx)",
				FridaAbiHandler.return_the_label_that_a_hook_prints_in_front_of_a_parameter(0,"this.context.ecx",""));
		expect_the_same(name_of_check,"a fastcall: the second argument, which is the one in EDX","arg_1(edx)",
				FridaAbiHandler.return_the_label_that_a_hook_prints_in_front_of_a_parameter(1,"this.context.edx",""));
		expect_the_same(name_of_check,"a fastcall: the third argument, which is the first thing on the stack and is frida's args[0]","arg_2",
				FridaAbiHandler.return_the_label_that_a_hook_prints_in_front_of_a_parameter(2,"args[0]",""));
		expect_the_same(name_of_check,"a fastcall: the fourth argument, which is frida's args[1]","arg_3",
				FridaAbiHandler.return_the_label_that_a_hook_prints_in_front_of_a_parameter(3,"args[1]",""));
		expect_the_same(name_of_check,"nothing to read leaves the label that the argument always had","args[2]",
				FridaAbiHandler.return_the_label_that_a_hook_prints_in_front_of_a_parameter(2,null,""));
		/*
		 * And the one thing a label must never carry: the javascript that reads the value. A label of this.context.ecx would make the
		 * hook print "this.context.ecx=" in front of the value, and the index of an args[] beside a different number would be worse.
		 */
		expect_the_same(name_of_check,"a label never carries the expression that reads the value","no",
				(FridaAbiHandler.return_the_label_that_a_hook_prints_in_front_of_a_parameter(0,"this.context.edx","").indexOf("this.context")>=0
						|| FridaAbiHandler.return_the_label_that_a_hook_prints_in_front_of_a_parameter(1,"args[0]","").indexOf("args[")>=0)?"yes":"no");
		/*And an argument that is where its own position says never says anything extra, whatever the option asked for*/
		expect_the_same(name_of_check,"an argument at its own position names no register","args[1]",
				FridaAbiHandler.return_the_label_that_a_hook_prints_in_front_of_a_parameter(1,"args[1]",""));

		/*
		 * The registers that a hook really read, which is what the comment at the top of it is written from. Taking them from the
		 * name of the convention instead would promise a read of EDX in a fastcall function that has only one argument.
		 */
		expect_the_same(name_of_check,"a hook that reads everything from the stack names no register","",
				FridaAbiHandler.return_the_registers_that_the_arguments_are_read_from(new String[]{"args[0]","args[1]"}));
		expect_the_same(name_of_check,"a hook whose first argument is in a register names it","this.context.ecx",
				FridaAbiHandler.return_the_registers_that_the_arguments_are_read_from(new String[]{"this.context.ecx","args[0]"}));
		expect_the_same(name_of_check,"a hook with two of them names both","this.context.ecx and this.context.edx",
				FridaAbiHandler.return_the_registers_that_the_arguments_are_read_from(new String[]{"this.context.ecx","this.context.edx","args[0]"}));
		expect_the_same(name_of_check,"a hook with three of them reads as a sentence","this.context.ecx, this.context.edx and this.context.eax",
				FridaAbiHandler.return_the_registers_that_the_arguments_are_read_from(new String[]{"this.context.ecx","this.context.edx","this.context.eax"}));
		expect_the_same(name_of_check,"a hook with no arguments at all names none","",
				FridaAbiHandler.return_the_registers_that_the_arguments_are_read_from(new String[]{}));
		expect_the_same(name_of_check,"nothing at all names none","",
				FridaAbiHandler.return_the_registers_that_the_arguments_are_read_from(null));

		/*The comment that is written when the hook did read the arguments from where the convention puts them*/
		expect_the_same(name_of_check,"the note of a thiscall names the register it read","yes",
				FridaAbiHandler.return_the_note_that_says_that_the_parameters_are_read_from_their_storage("__thiscall",
						new String[]{"this.context.ecx","args[0]"},"x86:LE:32:default","windows").indexOf("this.context.ecx")>=0?"yes":"no");
		expect_the_same(name_of_check,"the note of a fastcall names the second one as well","yes",
				FridaAbiHandler.return_the_note_that_says_that_the_parameters_are_read_from_their_storage("__fastcall",
						new String[]{"this.context.ecx","this.context.edx","args[0]"},"x86:LE:32:default","windows").indexOf("this.context.edx")>=0?"yes":"no");
		/*
		 * And the case that a note written from the name of the convention alone would get wrong: a fastcall function that has a
		 * single argument has nothing in EDX, and a comment that says its value is read from there sends the reader to a register
		 * that the hook never touched.
		 */
		expect_the_same(name_of_check,"the note of a fastcall with one argument does not promise a register that was never read","no",
				FridaAbiHandler.return_the_note_that_says_that_the_parameters_are_read_from_their_storage("__fastcall",
						new String[]{"this.context.ecx"},"x86:LE:32:default","windows").indexOf("this.context.edx")>=0?"yes":"no");
		/*
		 * The same mistake at the other end of the sentence: a function whose every argument is in a register has nothing left for
		 * args[] to carry, so the reader must not be sent there for the rest of something that has no rest.
		 */
		expect_the_same(name_of_check,"a function with every argument in a register is not sent to args[] for the rest","no",
				FridaAbiHandler.return_the_note_that_says_that_the_parameters_are_read_from_their_storage("__fastcall",
						new String[]{"this.context.ecx","this.context.edx"},"x86:LE:32:default","windows").indexOf("every argument after them")>=0?"yes":"no");
		expect_the_same(name_of_check,"and a function that does have one is sent there","yes",
				FridaAbiHandler.return_the_note_that_says_that_the_parameters_are_read_from_their_storage("__fastcall",
						new String[]{"this.context.ecx","this.context.edx","args[0]"},"x86:LE:32:default","windows").indexOf("every argument after them")>=0?"yes":"no");
		/*
		 * The note says that the work is done and the warning says that the reader has to do it. Writing both into one hook, or
		 * writing the one that tells the reader to go and read ECX in a hook that has already read it, would be worse than saying
		 * nothing, so the note must never carry the words of the warning.
		 */
		expect_the_same(name_of_check,"the note never tells the reader to go and read the register by hand","no",
				FridaAbiHandler.return_the_note_that_says_that_the_parameters_are_read_from_their_storage("__thiscall",
						new String[]{"this.context.ecx","args[0]"},"x86:LE:32:default","windows").indexOf("Read it with")>=0?"yes":"no");
		expect_the_same(name_of_check,"a function whose convention the database does not know still gets a note","yes",
				FridaAbiHandler.return_the_note_that_says_that_the_parameters_are_read_from_their_storage("unknown",
						new String[]{"this.context.ecx"},"x86:LE:32:default","windows").equals("")?"no":"yes");
		/*A hook that read nothing out of a register has nothing to say, whatever the name of its convention is*/
		expect_the_same(name_of_check,"nothing is noted for a hook that read every argument from the stack","",
				FridaAbiHandler.return_the_note_that_says_that_the_parameters_are_read_from_their_storage("__thiscall",
						new String[]{"args[0]","args[1]"},"x86:LE:32:default","windows"));
		expect_the_same(name_of_check,"nothing is noted where an abi was never a choice","",
				FridaAbiHandler.return_the_note_that_says_that_the_parameters_are_read_from_their_storage("__thiscall",
						new String[]{"this.context.ecx","args[0]"},"x86:LE:64:default","windows"));
		expect_the_same(name_of_check,"a convention that is not there at all is still noted by what was read","yes",
				FridaAbiHandler.return_the_note_that_says_that_the_parameters_are_read_from_their_storage(null,
						new String[]{"this.context.ecx"},"x86:LE:32:default","windows").indexOf("this.context.ecx")>=0?"yes":"no");
		/*
		 * The name of the convention comes from the database and ends up inside a line comment of the generated script. A name
		 * carrying a line break would end that comment early and leave the rest of it as code.
		 */
		expect_the_same(name_of_check,"a convention whose name carries a line break cannot break the comment","no",
				FridaAbiHandler.return_the_note_that_says_that_the_parameters_are_read_from_their_storage("__odd\ncall",
						new String[]{"this.context.ecx"},"x86:LE:32:default","windows").indexOf("\n")>=0?"yes":"no");

		/*
		 * And the whole decision at once, which can be asked for here now that it needs nothing but its arguments. A function of the
		 * database cannot be built by a check, so what these cases cover is every way of reaching the answer without consulting one,
		 * and every one of them has to come back with the args[<position>] that this plugin has always written.
		 */
		expect_the_same(name_of_check,"three arguments with the option off","args[0] args[1] args[2]",
				String.join(" ",FridaAbiHandler.return_the_javascript_that_reads_each_parameter(null,3,Boolean.FALSE,"x86:LE:32:default","windows")));
		expect_the_same(name_of_check,"three arguments with the option on but no function to ask","args[0] args[1] args[2]",
				String.join(" ",FridaAbiHandler.return_the_javascript_that_reads_each_parameter(null,3,Boolean.TRUE,"x86:LE:32:default","windows")));
		expect_the_same(name_of_check,"three arguments on a target where an abi was never a choice","args[0] args[1] args[2]",
				String.join(" ",FridaAbiHandler.return_the_javascript_that_reads_each_parameter(null,3,Boolean.TRUE,"AARCH64:LE:64:v8A","default")));
		expect_the_same(name_of_check,"a function with no arguments asks for nothing","",
				String.join(" ",FridaAbiHandler.return_the_javascript_that_reads_each_parameter(null,0,Boolean.TRUE,"x86:LE:32:default","windows")));
		expect_the_same(name_of_check,"a count of arguments that is not a count at all does not throw","",
				String.join(" ",FridaAbiHandler.return_the_javascript_that_reads_each_parameter(null,-1,Boolean.TRUE,"x86:LE:32:default","windows")));
		/*The same question asked the way the generator asks it, with the program itself and with nothing at all in place of it*/
		expect_the_same(name_of_check,"asked with the program, and with no function to ask about","args[0] args[1]",
				String.join(" ",FridaAbiHandler.return_the_javascript_that_reads_each_parameter(null,2,Boolean.TRUE,this.current_program)));
		expect_the_same(name_of_check,"asked with no program either","args[0] args[1]",
				String.join(" ",FridaAbiHandler.return_the_javascript_that_reads_each_parameter(null,2,Boolean.TRUE,(Program)null)));
		expect_the_same(name_of_check,"and the comment for a hook with no function to explain","",
				FridaAbiHandler.return_the_comment_about_the_arguments_of_an_attach_hook(null,new String[]{"this.context.ecx"},
						Boolean.TRUE,Boolean.TRUE,this.current_program));

		/*
		 * And the property that the whole thing rests on: a convention that puts every argument on the stack places argument number
		 * i at offset 4+4*i , which is exactly args[i]. So for such a function the answer is the text that was always written, and
		 * switching the option on cannot change a hook of a cdecl or a stdcall function by so much as a character.
		 */
		for (int i=0;i<8;i++)
		{
			expect_the_same(name_of_check,"argument number "+i+" of a function that passes everything on the stack is args["+i+"]",String.valueOf(i),
					String.valueOf(FridaAbiHandler.return_the_index_of_the_argument_of_frida_for_a_stack_offset(4+4*i)));
		}

		int how_many_errors=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR)-how_many_errors_before;
		this.report.add_summary_of_a_step(name_of_check,how_many_errors,0,
				(this.report.return_how_many_checks_were_run()-how_many_checks_before)+" cases");
	}

	/*
	 * The two pieces that decide what a name of the generated script is made of.
	 *
	 * The first turns any piece of text into something javascript accepts inside a name. What it has to deal with is not only
	 * the punctuation of a name from the database, such as a-program.1.0 or operator<< , but the colons that Address.toString()
	 * puts in front of an address that is not in the default space: an address of an overlay arrives as MYOVERLAY::00001000 ,
	 * and a name with a colon in it ends the statement it is written into.
	 *
	 * The second decides which module the resolver of the imports is told to look inside. It is the one place where a name from
	 * the database is written into the generated script without being escaped, and what makes that safe is that it refuses a
	 * name it does not like instead of repairing it, so the cases below are mostly names that have to be refused.
	 */
	protected void check_the_sanitizing_of_the_names()
	{
		String name_of_check="level 0: the sanitizing of the names";
		int how_many_errors_before=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR);

		expect_the_same(name_of_check,"an address of the default space","00401000",
				HookGeneratorUtils.return_sanitized_string_for_a_variable_name("00401000"));
		expect_the_same(name_of_check,"an address that carries the name of its space","ram_00401000",
				HookGeneratorUtils.return_sanitized_string_for_a_variable_name("ram:00401000"));
		expect_the_same(name_of_check,"an address of an overlay","MYOVERLAY__00001000",
				HookGeneratorUtils.return_sanitized_string_for_a_variable_name("MYOVERLAY::00001000"));
		expect_the_same(name_of_check,"the name of a program with dots and a dash","a_program_1_0",
				HookGeneratorUtils.return_sanitized_string_for_a_variable_name("a-program.1.0"));
		expect_the_same(name_of_check,"the name of a function that is an operator","operator__",
				HookGeneratorUtils.return_sanitized_string_for_a_variable_name("operator<<"));
		expect_the_same(name_of_check,"a name with a quote in it","it_s_a_name",
				HookGeneratorUtils.return_sanitized_string_for_a_variable_name("it's a name"));
		expect_the_same(name_of_check,"a name that is not there at all","",
				HookGeneratorUtils.return_sanitized_string_for_a_variable_name(null));

		expect_the_same(name_of_check,"an imported symbol of a dll","kernel32.dll",
				HookGeneratorUtils.return_sanitized_module_name_regex_for_dll_external_function_import("kernel32.dll::GetLastError"));
		expect_the_same(name_of_check,"the same one written in capitals","kernel32.dll",
				HookGeneratorUtils.return_sanitized_module_name_regex_for_dll_external_function_import("KERNEL32.DLL::GetLastError"));
		expect_the_same(name_of_check,"a name of a dll that carries a digit and an underscore","d3dx9_43.dll",
				HookGeneratorUtils.return_sanitized_module_name_regex_for_dll_external_function_import("d3dx9_43.dll::D3DXMatrixMultiply"));
		expect_the_same(name_of_check,"an imported symbol that names no dll at all","*",
				HookGeneratorUtils.return_sanitized_module_name_regex_for_dll_external_function_import("libc.so.6::malloc"));
		expect_the_same(name_of_check,"a name of a dll with a dash, which is refused and not repaired","*",
				HookGeneratorUtils.return_sanitized_module_name_regex_for_dll_external_function_import("api-ms-win-core-file-l1-1-0.dll::CreateFileW"));
		expect_the_same(name_of_check,"a name of a dll with a quote, which would end the literal it goes into","*",
				HookGeneratorUtils.return_sanitized_module_name_regex_for_dll_external_function_import("it's.dll::Foo"));
		expect_the_same(name_of_check,"no name at all","*",
				HookGeneratorUtils.return_sanitized_module_name_regex_for_dll_external_function_import(null));

		int how_many_errors=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR)-how_many_errors_before;
		this.report.add_summary_of_a_step(name_of_check,how_many_errors,0,"14 cases");
	}

	/*
	 * The escaping of a piece of text that is put inside a string literal of the generated script.
	 *
	 * The name of the program is the one that matters: it is written into the first line of every script, inside single
	 * quotes, and it comes from the project, where a user can call a program anything at all. A single quote in it used to end
	 * the literal and break the whole script, and a backslash used to be read by javascript as the beginning of an escape, so
	 * a program called a\btest.dll produced a script that was perfectly valid and looked for a module whose name carries a
	 * backspace, which fails at run time with a message that says nothing about the cause.
	 *
	 * These cases are here because no binary that this suite is ever run against will have such a name, so nothing else can
	 * reach them.
	 */
	protected void check_the_escaping_of_a_string_literal()
	{
		String name_of_check="level 0: the escaping of a string literal";
		int how_many_errors_before=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR);
		int how_many_checks_before=this.report.return_how_many_checks_were_run();

		expect_the_same(name_of_check,"a name with nothing to escape","a-program.1.0",
				HookGeneratorUtils.return_string_escaped_for_a_javascript_string_literal("a-program.1.0"));
		expect_the_same(name_of_check,"a name with a single quote","it\\'s a game.exe",
				HookGeneratorUtils.return_string_escaped_for_a_javascript_string_literal("it's a game.exe"));
		expect_the_same(name_of_check,"a name with a backslash","a\\\\btest.dll",
				HookGeneratorUtils.return_string_escaped_for_a_javascript_string_literal("a\\btest.dll"));
		expect_the_same(name_of_check,"a name with a double quote","he said \\\"hi\\\".exe",
				HookGeneratorUtils.return_string_escaped_for_a_javascript_string_literal("he said \"hi\".exe"));
		expect_the_same(name_of_check,"a name with a tab and a new line","a\\tb\\nc",
				HookGeneratorUtils.return_string_escaped_for_a_javascript_string_literal("a\tb\nc"));
		expect_the_same(name_of_check,"a name with a character that cannot be typed","a\\u0001b",
				HookGeneratorUtils.return_string_escaped_for_a_javascript_string_literal("a\u0001b"));
		expect_the_same(name_of_check,"a name that is not there at all","",
				HookGeneratorUtils.return_string_escaped_for_a_javascript_string_literal(null));
		/*
		 * The two separators that are line terminators of javascript without being control characters. A string literal of a modern
		 * runtime accepts them as they are, so this is not what breaks a script today, but they are written out all the same, so
		 * that the one escaper cannot be the weak one if somebody reaches for it where a line matters.
		 */
		expect_the_same(name_of_check,"a name carrying the line separator","a\\u2028b",
				HookGeneratorUtils.return_string_escaped_for_a_javascript_string_literal("a"+String.valueOf((char)0x2028)+"b"));
		expect_the_same(name_of_check,"a name carrying the paragraph separator","a\\u2029b",
				HookGeneratorUtils.return_string_escaped_for_a_javascript_string_literal("a"+String.valueOf((char)0x2029)+"b"));

		/*
		 * And the other half of the pair: the text that goes into a comment rather than into a literal. The sinks it guards are the
		 * operand of an instruction that could not be translated, the display name and the description of a type of a structure, and
		 * the name of a type that a replacement cannot accept. Every one of those comes out of the analysed file, and every one of
		 * them is written after a // , where any of the four line terminators ends the comment and leaves what follows as code.
		 */
		expect_the_same(name_of_check,"a comment with nothing to make safe","dword ptr [EAX + 0x4]",
				HookGeneratorUtils.return_text_safe_for_a_javascript_comment("dword ptr [EAX + 0x4]"));
		expect_the_same(name_of_check,"a comment that a line feed would cut short","a b",
				HookGeneratorUtils.return_text_safe_for_a_javascript_comment("a\nb"));
		expect_the_same(name_of_check,"a comment that a carriage return would cut short","a b",
				HookGeneratorUtils.return_text_safe_for_a_javascript_comment("a\rb"));
		expect_the_same(name_of_check,"a comment that the line separator would cut short","a b",
				HookGeneratorUtils.return_text_safe_for_a_javascript_comment("a"+String.valueOf((char)0x2028)+"b"));
		expect_the_same(name_of_check,"a comment that the paragraph separator would cut short","a b",
				HookGeneratorUtils.return_text_safe_for_a_javascript_comment("a"+String.valueOf((char)0x2029)+"b"));
		/*
		 * Careful with what this one expects. The slash is not dropped, a space is put in front of it, so the text keeps every
		 * character it arrived with and the two that would close a block comment are no longer next to each other.
		 */
		expect_the_same(name_of_check,"a comment that would close a block comment","a* /b",
				HookGeneratorUtils.return_text_safe_for_a_javascript_comment("a*/b"));
		expect_the_same(name_of_check,"a comment with no text at all","",
				HookGeneratorUtils.return_text_safe_for_a_javascript_comment(null));
		/*And the shape of the real attack: a symbol name that closes the comment and writes a statement after it*/
		expect_the_same(name_of_check,"an operand that tries to become a statement","no",
				HookGeneratorUtils.return_text_safe_for_a_javascript_comment("[EAX]\nsend({tag:'pwned'});//").indexOf("\n")>=0?"yes":"no");

		int how_many_errors=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR)-how_many_errors_before;
		this.report.add_summary_of_a_step(name_of_check,how_many_errors,0,
				(this.report.return_how_many_checks_were_run()-how_many_checks_before)+" cases");
	}

	/*
	 * The reader of the replies of the api. This is the piece that used to skip the first character of every reply and to
	 * stop at the first escaped quote, so the cases below are exactly those two problems plus the shapes that a real reply
	 * can have.
	 */
	protected void check_the_reader_of_the_replies_of_the_api()
	{
		String name_of_check="the reader of the replies of the api";
		int how_many_errors_before=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR);

		ChatGPTAPICaller caller=new ChatGPTAPICaller(TaskMonitor.DUMMY);

		expect_the_same(name_of_check,"a compact reply","3,17,42",
				caller.extract_message_from_json_response("{\"id\":\"x\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"3,17,42\"}}]}"));
		expect_the_same(name_of_check,"a reply that contains a quote","He said \"hi\" then 5,6",
				caller.extract_message_from_json_response("{\"choices\":[{\"message\":{\"content\":\"He said \\\"hi\\\" then 5,6\"}}]}"));
		expect_the_same(name_of_check,"a reply that contains a newline","line1\nline2",
				caller.extract_message_from_json_response("{\"choices\":[{\"message\":{\"content\":\"line1\\nline2\"}}]}"));
		expect_the_same(name_of_check,"a reply that contains a backslash","back\\slash",
				caller.extract_message_from_json_response("{\"choices\":[{\"message\":{\"content\":\"back\\\\slash\"}}]}"));
		expect_the_same(name_of_check,"a reply with an escaped unicode character","café",
				caller.extract_message_from_json_response("{\"choices\":[{\"message\":{\"content\":\"caf\\u00e9\"}}]}"));
		expect_the_same(name_of_check,"a reply with spaces around the colon","spaced",
				caller.extract_message_from_json_response("{\"choices\":[{\"message\":{\"content\": \"spaced\"}}]}"));
		/*A key whose name contains the word content, before the real one, must not be mistaken for it*/
		expect_the_same(name_of_check,"a reply with a decoy key before the content","7,8",
				caller.extract_message_from_json_response("{\"prompt_filter_results\":[{\"content_filter_results\":{\"hate\":{\"filtered\":false}}}],\"choices\":[{\"message\":{\"content\":\"7,8\"}}]}"));
		/*A reply that carries no text at all has to be reported as no reply, and not as an empty one*/
		if (caller.extract_message_from_json_response("{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":null}}]}")!=null)
		{
			this.report.add_error(name_of_check,"a reply with no content",
					"A reply whose content is null should be reported as no reply at all","the reader returned something instead of null",0);
		}
		this.report.count_one_check_that_was_run();

		int how_many_errors=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR)-how_many_errors_before;
		this.report.add_summary_of_a_step("level 0: the reader of the replies of the api",how_many_errors,0,"8 cases");
	}

	/*----------------------------------------------------------------------------------------------------------------*/

	protected void check_the_parsers_of_the_computed_calls()
	{
		String language_of_the_program=this.current_program.getLanguage().getLanguageID().toString();

		if (language_of_the_program.indexOf("x86:LE:64")>=0)
		{
			check_the_parser_of_x64();
		}
		else
		{
			this.report.add_skipped_step("level 0: the parser of the computed calls of x64","the loaded program is "+language_of_the_program);
		}

		if (language_of_the_program.indexOf("AARCH64:LE:64")>=0)
		{
			check_the_parser_of_aarch64();
		}
		else
		{
			this.report.add_skipped_step("level 0: the parser of the computed calls of AArch64","the loaded program is "+language_of_the_program);
		}

		if (language_of_the_program.indexOf("ARM:LE:32")>=0)
		{
			check_the_parser_of_arm32();
		}
		else
		{
			this.report.add_skipped_step("level 0: the parser of the computed calls of ARM32","the loaded program is "+language_of_the_program);
		}
	}

	protected void check_the_parser_of_x64()
	{
		String name_of_check="the parser of the computed calls of x64";
		int how_many_errors_before=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR);
		ParserOfComputedCalls parser=new X86ParserOfComputedCall(this.current_program,this.name_of_the_module_variable);
		int how_many_cases=0;

		expect_the_same(name_of_check,"a call through a register","(this.context.rax)",
				parser.create_frida_code_for_call_arg("call","rax",null)); how_many_cases++;
		expect_the_same(name_of_check,"a call through a dereferenced register","(this.context.rax).readPointer()",
				parser.create_frida_code_for_call_arg("call","qword ptr [rax]",null)); how_many_cases++;
		expect_the_same(name_of_check,"a base and a scaled index","(this.context.rax.add(this.context.rdx.toInt32()*0x8)).readPointer()",
				parser.create_frida_code_for_call_arg("call","qword ptr [rax + rdx*0x8]",null)); how_many_cases++;
		/*The negative displacement that Ghidra writes as "+ -0x8". It used to produce an add() with nothing inside it*/
		expect_the_same(name_of_check,"a negative displacement","(this.context.rbp.sub(0x8)).readPointer()",
				parser.create_frida_code_for_call_arg("call","qword ptr [rbp + -0x8]",null)); how_many_cases++;
		expect_the_same(name_of_check,"a base, a scaled index and a displacement","(this.context.r12.add(this.context.r13.toInt32()*0x8).add(0x20)).readPointer()",
				parser.create_frida_code_for_call_arg("jmp","qword ptr [r12 + r13*0x8 + 0x20]",null)); how_many_cases++;
		expect_the_same(name_of_check,"a 32 bit register in an address expression","(this.context.r11)",
				parser.create_frida_code_for_call_arg("call","r11d",null)); how_many_cases++;
		/*The forms that cannot be translated have to come back empty, so that the caller writes a comment instead of code*/
		expect_the_same(name_of_check,"a segment override is refused","",
				parser.create_frida_code_for_call_arg("call","qword ptr fs:[0x30]",null)); how_many_cases++;
		expect_the_same(name_of_check,"a register multiplied by a register is refused","",
				parser.create_frida_code_for_call_arg("call","qword ptr [rax + rbx*rcx]",null)); how_many_cases++;

		/*An absolute address has to be turned into an offset from the base of the module. The expected value is computed from the image base of the loaded program*/
		Address image_base=this.current_program.getImageBase();
		long absolute_address_to_test=image_base.getOffset()+0x1234L;
		expect_the_same(name_of_check,"an absolute address becomes an offset from the module",
				"(Process.getModuleByName("+this.name_of_the_module_variable+").base.add(0x1234)).readPointer()",
				parser.create_frida_code_for_call_arg("call","qword ptr [0x"+Long.toHexString(absolute_address_to_test)+"]",null)); how_many_cases++;

		/*
		 * The RIP relative form. It needs a real instruction, because the displacement of x86 is relative to the address of
		 * the instruction that follows the current one, and that is the whole point of the check.
		 */
		Instruction some_instruction=return_the_first_instruction_of_the_program();
		if (some_instruction==null)
		{
			this.report.add_skipped_step("level 0: the RIP relative form of x64","the program has no instruction to use for the check");
		}
		else
		{
			long address_of_the_next_instruction=some_instruction.getAddress().getOffset()+some_instruction.getLength();
			long expected_offset=address_of_the_next_instruction+0x10L-image_base.getOffset();
			String expected_code;
			if (expected_offset>=0)
			{
				expected_code="(Process.getModuleByName("+this.name_of_the_module_variable+").base.add(0x"+Long.toHexString(expected_offset)+")).readPointer()";
			}
			else
			{
				expected_code="(Process.getModuleByName("+this.name_of_the_module_variable+").base.sub(0x"+Long.toHexString(-expected_offset)+")).readPointer()";
			}
			expect_the_same(name_of_check,"a RIP relative address is resolved with the length of the instruction",expected_code,
					parser.create_frida_code_for_call_arg("call","qword ptr [rip + 0x10]",some_instruction)); how_many_cases++;
			/*Without an instruction the form cannot be resolved, and it has to be refused instead of guessed*/
			expect_the_same(name_of_check,"a RIP relative address without an instruction is refused","",
					parser.create_frida_code_for_call_arg("call","qword ptr [rip + 0x10]",null)); how_many_cases++;
		}

		int how_many_errors=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR)-how_many_errors_before;
		this.report.add_summary_of_a_step("level 0: "+name_of_check,how_many_errors,0,how_many_cases+" cases");
	}

	protected void check_the_parser_of_aarch64()
	{
		String name_of_check="the parser of the computed calls of AArch64";
		int how_many_errors_before=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR);
		ParserOfComputedCalls parser=new ARM64ParserOfComputedCall(this.current_program,this.name_of_the_module_variable);
		int how_many_cases=0;

		expect_the_same(name_of_check,"a branch through a register","(this.context.x8)",
				parser.create_frida_code_for_call_arg("blr","x8",null)); how_many_cases++;
		expect_the_same(name_of_check,"a branch through x16","(this.context.x16)",
				parser.create_frida_code_for_call_arg("br","x16",null)); how_many_cases++;
		/*The context of frida names the last two registers fp and lr, it has no x29 and no x30*/
		expect_the_same(name_of_check,"x29 is named fp in the context","(this.context.fp)",
				parser.create_frida_code_for_call_arg("blr","x29",null)); how_many_cases++;
		expect_the_same(name_of_check,"x30 is named lr in the context","(this.context.lr)",
				parser.create_frida_code_for_call_arg("blr","x30",null)); how_many_cases++;
		expect_the_same(name_of_check,"the authenticated form with the key a","(this.context.x8.strip(\"ia\"))",
				parser.create_frida_code_for_call_arg("blraaz","x8",null)); how_many_cases++;
		expect_the_same(name_of_check,"the authenticated form with the key b","(this.context.x8.strip(\"ib\"))",
				parser.create_frida_code_for_call_arg("blrabz","x8",null)); how_many_cases++;
		expect_the_same(name_of_check,"the authenticated branch without a link","(this.context.x17.strip(\"ia\"))",
				parser.create_frida_code_for_call_arg("braaz","x17",null)); how_many_cases++;
		/*The variants that carry their modifier in a second operand: only the first operand holds the destination*/
		expect_the_same(name_of_check,"the authenticated form with a modifier","(this.context.x8.strip(\"ia\"))",
				parser.create_frida_code_for_call_arg("blraa","x8,x9",null)); how_many_cases++;
		expect_the_same(name_of_check,"the authenticated form with a modifier and a space","(this.context.x16.strip(\"ib\"))",
				parser.create_frida_code_for_call_arg("brab","x16, x17",null)); how_many_cases++;
		expect_the_same(name_of_check,"the zero register is refused","",
				parser.create_frida_code_for_call_arg("blr","xzr",null)); how_many_cases++;
		expect_the_same(name_of_check,"a register that does not exist is refused","",
				parser.create_frida_code_for_call_arg("blr","x31",null)); how_many_cases++;
		expect_the_same(name_of_check,"a 32 bit register is refused","",
				parser.create_frida_code_for_call_arg("blr","w8",null)); how_many_cases++;
		/*bx belongs to ARM32 and does not exist in AArch64*/
		expect_the_same(name_of_check,"an ARM32 mnemonic is refused","",
				parser.create_frida_code_for_call_arg("bx","x8",null)); how_many_cases++;

		int how_many_errors=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR)-how_many_errors_before;
		this.report.add_summary_of_a_step("level 0: "+name_of_check,how_many_errors,0,how_many_cases+" cases");
	}

	protected void check_the_parser_of_arm32()
	{
		String name_of_check="the parser of the computed calls of ARM32";
		int how_many_errors_before=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR);
		ParserOfComputedCalls parser=new ARM32ParserOfComputedCall(this.current_program,this.name_of_the_module_variable);
		int how_many_cases=0;
		String the_mask="0xfffffffe";

		expect_the_same(name_of_check,"a branch through a register","(this.context.r3.and("+the_mask+"))",
				parser.create_frida_code_for_call_arg("bx","r3",null)); how_many_cases++;
		expect_the_same(name_of_check,"a branch with a link through a register","(this.context.r3.and("+the_mask+"))",
				parser.create_frida_code_for_call_arg("blx","r3",null)); how_many_cases++;
		expect_the_same(name_of_check,"a branch through the link register","(this.context.lr.and("+the_mask+"))",
				parser.create_frida_code_for_call_arg("bx","lr",null)); how_many_cases++;
		/*The condition suffix and the wide suffix of Thumb have to be recognized*/
		expect_the_same(name_of_check,"a conditional branch","(this.context.r3.and("+the_mask+"))",
				parser.create_frida_code_for_call_arg("bxeq","r3",null)); how_many_cases++;
		expect_the_same(name_of_check,"the wide form of Thumb","(this.context.r3.and("+the_mask+"))",
				parser.create_frida_code_for_call_arg("blx.w","r3",null)); how_many_cases++;
		expect_the_same(name_of_check,"the alternative name of a register","(this.context.r12.and("+the_mask+"))",
				parser.create_frida_code_for_call_arg("bx","ip",null)); how_many_cases++;
		expect_the_same(name_of_check,"a write to the program counter","(this.context.r3.and("+the_mask+"))",
				parser.create_frida_code_for_call_arg("mov","pc,r3",null)); how_many_cases++;
		/*movs ends with the letters of the vs condition, and it must not be mistaken for a conditional mov*/
		expect_the_same(name_of_check,"a mnemonic that ends like a condition","(this.context.r5.and("+the_mask+"))",
				parser.create_frida_code_for_call_arg("movs","pc,r5",null)); how_many_cases++;
		expect_the_same(name_of_check,"a mov that is not a jump is refused","",
				parser.create_frida_code_for_call_arg("mov","r0,r3",null)); how_many_cases++;
		expect_the_same(name_of_check,"a load into the program counter","(this.context.r12.add(0x8).readPointer().and("+the_mask+"))",
				parser.create_frida_code_for_call_arg("ldr","pc,[r12,#0x8]",null)); how_many_cases++;
		expect_the_same(name_of_check,"a load with a negative offset","(this.context.r11.sub(0x4).readPointer().and("+the_mask+"))",
				parser.create_frida_code_for_call_arg("ldr","pc,[r11,#-0x4]",null)); how_many_cases++;
		expect_the_same(name_of_check,"a load with a writeback","(this.context.r12.add(0x8).readPointer().and("+the_mask+"))",
				parser.create_frida_code_for_call_arg("ldr","pc,[r12,#0x8]!",null)); how_many_cases++;
		/*Reading the program counter as an operand cannot be reproduced, because its value depends on the instruction set*/
		expect_the_same(name_of_check,"a load relative to the program counter is refused","",
				parser.create_frida_code_for_call_arg("ldr","pc,[pc,#0x8]",null)); how_many_cases++;
		expect_the_same(name_of_check,"a shifted register offset is refused","",
				parser.create_frida_code_for_call_arg("ldr","pc,[r3,r2,lsl #0x2]",null)); how_many_cases++;
		expect_the_same(name_of_check,"a load that does not write the program counter is refused","",
				parser.create_frida_code_for_call_arg("ldr","r0,[r3]",null)); how_many_cases++;
		expect_the_same(name_of_check,"a branch to an immediate is refused","",
				parser.create_frida_code_for_call_arg("blx","0x1234",null)); how_many_cases++;

		int how_many_errors=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR)-how_many_errors_before;
		this.report.add_summary_of_a_step("level 0: "+name_of_check,how_many_errors,0,how_many_cases+" cases");
	}

	/*----------------------------------------------------------------------------------------------------------------*/

	protected Instruction return_the_first_instruction_of_the_program()
	{
		InstructionIterator instruction_iterator=this.current_program.getListing().getInstructions(true);
		if (instruction_iterator!=null && instruction_iterator.hasNext())
		{
			return instruction_iterator.next();
		}
		return null;
	}

	protected void expect_the_same(String name_of_check,String name_of_the_case,String what_was_expected,String what_came_out)
	{
		this.report.count_one_check_that_was_run();
		if (what_came_out==null)
		{
			what_came_out="<null>";
		}
		if (what_was_expected.equals(what_came_out))
		{
			return;
		}
		this.report.add_error(name_of_check,name_of_the_case,
				"The case '"+name_of_the_case+"' did not produce what was expected",
				"expected: "+(what_was_expected.equals("")?"<the empty string, so that a comment is emitted>":what_was_expected)+"   but got: "+(what_came_out.equals("")?"<the empty string>":what_came_out),0);
	}
}
