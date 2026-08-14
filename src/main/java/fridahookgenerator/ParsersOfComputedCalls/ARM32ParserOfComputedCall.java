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
 * This class translates the computed calls/jumps of ARM (32 bit) and Thumb into frida code.
 *
 * The forms that are handled are the ones whose destination can be calculated from the registers of the hooked thread:
 *   bx <reg> , blx <reg> , bxj <reg>          the destination is held in the register
 *   mov pc,<reg>                              writing to the program counter is an interworking branch
 *   ldr pc,[<reg>] and ldr pc,[<reg>,#imm]    the destination is loaded from memory (the veneers of the PLT look like this)
 * All of them may carry a condition suffix (bxeq, ldrne, ...) and the wide/narrow suffixes of Thumb (.w , .n).
 *
 * Two forms are deliberately not handled:
 *   - anything that reads the program counter as a source operand (for example "ldr pc,[pc,#0x8]"). When the program
 *     counter is read as an operand, its value is the address of the instruction plus 8 in ARM state and plus 4 in Thumb
 *     state, and the state cannot be told apart reliably from the text of the instruction alone.
 *   - the table branches (tbb/tbh) and the jump tables that are built with an add to the program counter, whose
 *     destination depends on the contents of a table.
 * For those, the empty string is returned and the caller emits a comment instead of code.
 *
 * Careful: in ARM the least significant bit of the destination of an interworking branch is not part of the address, it
 * selects the instruction set (0 for ARM, 1 for Thumb). It is masked out, so that the address that is printed and looked
 * up in the module map is the real one.
 */
public class ARM32ParserOfComputedCall implements ParserOfComputedCalls{

	private Program incoming_program;
	private Language current_program_language;
	private Processor current_program_processor;
	private String incoming_module_name_sanitized;
	private String mask_that_removes_the_instruction_set_bit="0xfffffffe";

	public ARM32ParserOfComputedCall(Program incoming_program, String incoming_module_name_sanitized) {
		this.incoming_program=incoming_program;
		this.current_program_language = this.incoming_program.getLanguage();
		this.current_program_processor = this.current_program_language.getProcessor();
		this.incoming_module_name_sanitized=incoming_module_name_sanitized;
	}


	public String create_frida_code_for_call_arg(String mnemonic,String arg,Instruction incoming_instruction)
	{
		if (arg==null || arg.trim().equals("") || mnemonic==null)
		{
			return "";
		}
		arg=arg.trim().toLowerCase();
		String base_mnemonic=return_base_mnemonic(mnemonic.trim().toLowerCase());

		if (base_mnemonic.equals("bx") || base_mnemonic.equals("blx") || base_mnemonic.equals("bxj"))
		{
			String register_of_frida_context=return_frida_register_for_token(arg);
			if (register_of_frida_context.equals(""))
			{
				return ""; //a blx to an immediate is not a computed call, and the program counter cannot be used here
			}
			return "(this.context."+register_of_frida_context+".and("+this.mask_that_removes_the_instruction_set_bit+"))";
		}

		if (base_mnemonic.equals("mov") || base_mnemonic.equals("movs"))
		{
			/*Only a "mov pc,<reg>" is a computed jump, and the destination is the second operand*/
			int position_of_first_comma=arg.indexOf(",");
			if (position_of_first_comma<0)
			{
				return "";
			}
			if (!arg.substring(0,position_of_first_comma).trim().equals("pc"))
			{
				return "";
			}
			String register_of_frida_context=return_frida_register_for_token(arg.substring(position_of_first_comma+1));
			if (register_of_frida_context.equals(""))
			{
				return "";
			}
			return "(this.context."+register_of_frida_context+".and("+this.mask_that_removes_the_instruction_set_bit+"))";
		}

		if (base_mnemonic.equals("ldr"))
		{
			/*Only a "ldr pc,[...]" is a computed jump, and the destination is loaded from the memory operand*/
			int position_of_first_comma=arg.indexOf(",");
			if (position_of_first_comma<0)
			{
				return "";
			}
			if (!arg.substring(0,position_of_first_comma).trim().equals("pc"))
			{
				return "";
			}
			String frida_code_for_the_memory_operand=create_frida_code_for_memory_operand(arg.substring(position_of_first_comma+1));
			if (frida_code_for_the_memory_operand.equals(""))
			{
				return "";
			}
			return "("+frida_code_for_the_memory_operand+".readPointer().and("+this.mask_that_removes_the_instruction_set_bit+"))";
		}

		return "";
	}


	/*
	 * Translates the address of a memory operand. Only the forms whose address is known from a single base register are
	 * handled: [reg] , [reg,#imm] , [reg,#imm]! and [reg],#imm . A scaled or register offset ([r3,r2,lsl #0x2]) needs
	 * the barrel shifter to be reproduced and is not handled.
	 */
	protected String create_frida_code_for_memory_operand(String memory_operand)
	{
		if (memory_operand==null)
		{
			return "";
		}
		String operand_to_examine=memory_operand.trim();
		if (operand_to_examine.endsWith("!"))
		{
			//pre indexed with writeback, the address that is used is the same one
			operand_to_examine=operand_to_examine.substring(0,operand_to_examine.length()-1).trim();
		}
		if (!operand_to_examine.startsWith("["))
		{
			return "";
		}
		int position_of_closing_bracket=operand_to_examine.indexOf("]");
		if (position_of_closing_bracket<0)
		{
			return "";
		}
		/*Anything after the closing bracket is a post indexed offset, which is applied after the access and therefore does not affect the address*/
		String contents_of_the_brackets=operand_to_examine.substring(1,position_of_closing_bracket).trim();

		String[] parts_of_the_operand=contents_of_the_brackets.split(",");
		if (parts_of_the_operand.length<1 || parts_of_the_operand.length>2)
		{
			return "";
		}

		String register_of_frida_context=return_frida_register_for_token(parts_of_the_operand[0]);
		if (register_of_frida_context.equals(""))
		{
			return ""; //this is also where a [pc,#imm] ends up, as the program counter is not accepted as a base register
		}
		if (parts_of_the_operand.length==1)
		{
			return "this.context."+register_of_frida_context;
		}

		String offset_of_the_operand=parts_of_the_operand[1].trim();
		if (!offset_of_the_operand.startsWith("#"))
		{
			return ""; //a register offset, possibly shifted, which is not handled
		}
		Long value_of_the_offset=return_value_of_immediate(offset_of_the_operand.substring(1));
		if (value_of_the_offset==null)
		{
			return "";
		}
		if (value_of_the_offset.longValue()>=0)
		{
			return "this.context."+register_of_frida_context+".add(0x"+Long.toHexString(value_of_the_offset.longValue())+")";
		}
		return "this.context."+register_of_frida_context+".sub(0x"+Long.toHexString(-value_of_the_offset.longValue())+")";
	}


	protected Long return_value_of_immediate(String immediate)
	{
		if (immediate==null)
		{
			return null;
		}
		String immediate_to_examine=immediate.trim().toLowerCase();
		Boolean value_is_negative=false;
		if (immediate_to_examine.startsWith("-"))
		{
			value_is_negative=true;
			immediate_to_examine=immediate_to_examine.substring(1).trim();
		}
		try {
			long value;
			if (immediate_to_examine.startsWith("0x"))
			{
				value=Long.parseLong(immediate_to_examine.substring(2),16);
			}
			else
			{
				value=Long.parseLong(immediate_to_examine,10);
			}
			if (value_is_negative)
			{
				value=-value;
			}
			return Long.valueOf(value);
		}
		catch (NumberFormatException ex)
		{
			return null;
		}
	}


	/*
	 * Removes the wide/narrow suffix of Thumb and the condition suffix, and returns the mnemonic itself.
	 * Careful: the condition suffix can only be removed when what is left is a mnemonic that we handle. Removing it
	 * blindly would turn "movs" (which ends with the "vs" condition) into something meaningless.
	 */
	protected String return_base_mnemonic(String mnemonic)
	{
		String[] mnemonics_that_are_handled={"bx","blx","bxj","mov","movs","ldr"};
		String[] condition_suffixes={"eq","ne","cs","hs","cc","lo","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","al"};

		String mnemonic_to_examine=mnemonic;
		if (mnemonic_to_examine.endsWith(".w") || mnemonic_to_examine.endsWith(".n"))
		{
			mnemonic_to_examine=mnemonic_to_examine.substring(0,mnemonic_to_examine.length()-2);
		}

		for (int i=0;i<mnemonics_that_are_handled.length;i++)
		{
			if (mnemonic_to_examine.equals(mnemonics_that_are_handled[i]))
			{
				return mnemonics_that_are_handled[i];
			}
		}

		if (mnemonic_to_examine.length()>2)
		{
			String possible_condition_suffix=mnemonic_to_examine.substring(mnemonic_to_examine.length()-2);
			String mnemonic_without_the_condition=mnemonic_to_examine.substring(0,mnemonic_to_examine.length()-2);
			for (int i=0;i<condition_suffixes.length;i++)
			{
				if (!possible_condition_suffix.equals(condition_suffixes[i]))
				{
					continue;
				}
				for (int j=0;j<mnemonics_that_are_handled.length;j++)
				{
					if (mnemonic_without_the_condition.equals(mnemonics_that_are_handled[j]))
					{
						return mnemonics_that_are_handled[j];
					}
				}
			}
		}

		return "";
	}


	/*
	 * Returns the name of the frida CpuContext field for a register token, or the empty string when the token is not a
	 * register that we can use. Careful: the program counter is never accepted, because when it is read as an operand
	 * its value is the address of the instruction plus 8 in ARM state (plus 4 in Thumb state), and not the address of
	 * the instruction itself, which is what a frida hook would give.
	 */
	protected String return_frida_register_for_token(String token)
	{
		if (token==null)
		{
			return "";
		}
		String token_to_examine=token.trim().toLowerCase();
		if (token_to_examine.equals(""))
		{
			return "";
		}

		for (int i=0;i<=12;i++)
		{
			if (token_to_examine.equals("r"+i))
			{
				return "r"+i;
			}
		}
		if (token_to_examine.equals("sp") || token_to_examine.equals("r13"))
		{
			return "sp";
		}
		if (token_to_examine.equals("lr") || token_to_examine.equals("r14"))
		{
			return "lr";
		}
		/*The alternative names of the registers that the ARM procedure call standard gives*/
		if (token_to_examine.equals("sb")) { return "r9"; }
		if (token_to_examine.equals("sl")) { return "r10"; }
		if (token_to_examine.equals("fp")) { return "r11"; }
		if (token_to_examine.equals("ip")) { return "r12"; }

		return "";
	}

}
