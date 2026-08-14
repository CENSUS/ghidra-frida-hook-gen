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

package fridahookgenerator.ParsersOfComputedCalls;

import fridahookgenerator.ParserOfComputedCalls;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

/*
 * This class basically returns the argument to BLR <arg> in ARM64, translated into frida code. Much simpler than x64.
 *
 * All the branches to a register are handled: blr/br, the variants that authenticate against a zero modifier
 * (blraaz/blrabz/braaz/brabz), and the ones that carry their modifier in a second operand (blraa/blrab/braa/brab), of
 * which only the first operand holds the destination. The destination of every authenticated variant has to be stripped
 * of its pointer authentication code.
 */
public class ARM64ParserOfComputedCall implements ParserOfComputedCalls{

	private Program incoming_program;
	private Language current_program_language;
	private Processor current_program_processor;
	private String incoming_module_name_sanitized;

	public ARM64ParserOfComputedCall(Program incoming_program, String incoming_module_name_sanitized) {
		this.incoming_program=incoming_program;
		this.current_program_language = this.incoming_program.getLanguage();
		this.current_program_processor = this.current_program_language.getProcessor();
		this.incoming_module_name_sanitized=incoming_module_name_sanitized;
	}


	public String create_frida_code_for_call_arg(String mnemonic,String arg,Instruction incoming_instruction)
	{
		/*Careful: the comparisons have to be done with equals(), as the incoming mnemonic and argument are runtime strings (they come from Instruction.getMnemonicString()/toString()) and are therefore not interned*/
		if (arg==null || arg.trim().equals("") || mnemonic==null)
		{
			return "";
		}
		arg=arg.trim().toLowerCase();
		mnemonic=mnemonic.trim().toLowerCase();

		/*The authenticated variants that carry a modifier have it in a second operand (blraa x8,x9), and only the first one holds the destination*/
		if (arg.indexOf(",")>=0)
		{
			arg=arg.split(",")[0].trim();
		}

		/*x0 up to x30. Careful: xzr is not accepted, as it never holds the destination of a branch, and neither are the 32 bit registers, as they cannot hold an address*/
		if (!arg.matches("x([0-9]|1[0-9]|2[0-9]|30)"))
		{
			return "";
		}

		/*The frida CpuContext of AArch64 names the last two registers fp and lr, it does not have an x29/x30 field*/
		String register_of_frida_context=arg;
		if (arg.equals("x29")) { register_of_frida_context="fp"; }
		if (arg.equals("x30")) { register_of_frida_context="lr"; }

		/*
		 * The pointer authentication code has to be removed from the destination of the authenticated variants.
		 * strip() removes it without authenticating (it is the equivalent of an xpaci), so it does not need to know the
		 * modifier, and it can therefore be used for the variants that carry one in a second operand as well.
		 */
		String suffix_that_strips_the_pointer_authentication_code="";
		if (mnemonic.equals("blr") || mnemonic.equals("br"))
		{
			suffix_that_strips_the_pointer_authentication_code="";
		}
		else if (mnemonic.equals("blraa") || mnemonic.equals("blraaz") || mnemonic.equals("braa") || mnemonic.equals("braaz"))
		{
			suffix_that_strips_the_pointer_authentication_code=".strip(\"ia\")";
		}
		else if (mnemonic.equals("blrab") || mnemonic.equals("blrabz") || mnemonic.equals("brab") || mnemonic.equals("brabz"))
		{
			suffix_that_strips_the_pointer_authentication_code=".strip(\"ib\")";
		}
		else
		{
			return "";
		}

		return "(this.context."+register_of_frida_context+suffix_that_strips_the_pointer_authentication_code+")";
	}
}
