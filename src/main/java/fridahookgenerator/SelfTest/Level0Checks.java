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
	 * The two pieces that decide what a name of the generated script is made of.
	 *
	 * The first turns any piece of text into something javascript accepts inside a name. What it has to deal with is not only
	 * the punctuation of a name from the database, such as gimp-2.10 or operator<< , but the colons that Address.toString()
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
		expect_the_same(name_of_check,"the name of a program with dots and a dash","gimp_2_10",
				HookGeneratorUtils.return_sanitized_string_for_a_variable_name("gimp-2.10"));
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

		expect_the_same(name_of_check,"a name with nothing to escape","gimp-2.10",
				HookGeneratorUtils.return_string_escaped_for_a_javascript_string_literal("gimp-2.10"));
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

		int how_many_errors=this.report.return_how_many_of_severity(SelfTestFinding.Severity.ERROR)-how_many_errors_before;
		this.report.add_summary_of_a_step(name_of_check,how_many_errors,0,"7 cases");
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
