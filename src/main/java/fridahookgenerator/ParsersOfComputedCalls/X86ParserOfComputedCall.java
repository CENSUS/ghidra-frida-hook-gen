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

import java.util.ArrayList;

import fridahookgenerator.HookGeneratorUtils;
import fridahookgenerator.ParserOfComputedCalls;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

/*
 * This class tries to decode the argument to CALL <arg> in x86, and translate them into frida code.
 *
 * The argument of a computed call is an address expression, which is a sum of signed terms. Every term is either a
 * register, a register multiplied by a scale, or a constant. The expression is translated into frida code by picking
 * one of the terms as the base (a NativePointer) and by adding/subtracting the remaining ones to it.
 *
 * Two forms need special treatment:
 *  - RIP relative addressing. It cannot be translated into "this.context.pc + displacement", because on x86 the
 *    displacement is relative to the address of the *next* instruction, while the pc of a frida hook is the address of
 *    the hooked instruction itself. The destination is statically known however, so it is calculated here and emitted
 *    as an offset from the base of the module.
 *  - An expression that contains no unscaled register. In that case the constant of the expression is not a
 *    displacement but an absolute virtual address (for example the base of a jump table), so it is emitted relative to
 *    the base of the module as well, after the image base has been subtracted from it.
 */
public class X86ParserOfComputedCall implements ParserOfComputedCalls{

	private Program incoming_program;
	private Language current_program_language;
	private Processor current_program_processor;
	private String incoming_module_name_sanitized;
	private Boolean we_are_in_64bit_mode;

	public X86ParserOfComputedCall(Program incoming_program, String incoming_module_name_sanitized) {
		this.incoming_program=incoming_program;
		this.current_program_language = this.incoming_program.getLanguage();
		this.current_program_processor = this.current_program_language.getProcessor();
		this.incoming_module_name_sanitized=incoming_module_name_sanitized;
		this.we_are_in_64bit_mode=(this.current_program_language.getLanguageID().toString().indexOf("x86:LE:64")>=0);
	}


	public String create_frida_code_for_call_arg(String mnemonic,String arg,Instruction incoming_instruction)
	{
		String retval="";
		Boolean is_ptr_dereference=false;

		if (arg==null || arg.trim().equals(""))
		{
			return "";
		}
		arg=arg.replaceAll(".?word ptr","").trim();
		if (arg.equals(""))
		{
			return "";
		}

		if (arg.charAt(0)=='[' && arg.charAt(arg.length()-1)==']')
		{
			is_ptr_dereference=true;
			arg=arg.substring(1, arg.length()-1).trim(); //Strip the dereference brackets and continue
			if (!arg.matches("[0-9a-zA-Z\\+\\*\\-\\ ]*")) //Allowed characters
			{
				return "";
			}
		}

		String frida_code_for_the_address_expression=create_frida_code_for_address_expression(arg,incoming_instruction);
		if (frida_code_for_the_address_expression.equals(""))
		{
			//the expression could not be translated, the caller will emit a comment instead of code
			return "";
		}

		retval="("+frida_code_for_the_address_expression+")";
		if (is_ptr_dereference)
		{
			retval+=".readPointer()";
		}

		return retval;
	}


	protected String create_frida_code_for_address_expression(String arg, Instruction incoming_instruction)
	{
		ArrayList<String> terms_of_the_expression=new ArrayList<String>();
		ArrayList<Boolean> term_is_added=new ArrayList<Boolean>();  //false means that the term is subtracted

		if (!split_expression_into_signed_terms(arg,terms_of_the_expression,term_is_added))
		{
			return "";
		}

		/*First of all, see if the instruction pointer participates in the expression, as it needs to be resolved statically*/
		Boolean the_instruction_pointer_participates=false;
		for (int i=0;i<terms_of_the_expression.size();i++)
		{
			if (is_token_the_instruction_pointer(terms_of_the_expression.get(i)))
			{
				the_instruction_pointer_participates=true;
			}
		}

		if (the_instruction_pointer_participates)
		{
			return create_frida_code_for_instruction_pointer_relative_expression(terms_of_the_expression,term_is_added,incoming_instruction);
		}

		/*
		 * Find the term which will become the base of the calculation. An unscaled register is preferred, because then
		 * every constant of the expression is a displacement. If there is no such register, then the constant of the
		 * expression is an absolute address and it becomes the base.
		 */
		int index_of_the_base_term=-1;
		for (int i=0;i<terms_of_the_expression.size();i++)
		{
			if (term_is_added.get(i).booleanValue() && !return_frida_register_for_token(terms_of_the_expression.get(i)).equals(""))
			{
				index_of_the_base_term=i;
				break;
			}
		}

		String frida_code="";
		if (index_of_the_base_term>=0)
		{
			frida_code="this.context."+return_frida_register_for_token(terms_of_the_expression.get(index_of_the_base_term));
		}
		else
		{
			for (int i=0;i<terms_of_the_expression.size();i++)
			{
				if (term_is_added.get(i).booleanValue() && return_value_of_constant_token(terms_of_the_expression.get(i))!=null)
				{
					index_of_the_base_term=i;
					break;
				}
			}
			if (index_of_the_base_term<0)
			{
				return ""; //neither a register nor a constant to start from
			}
			frida_code=create_frida_code_for_virtual_address(return_value_of_constant_token(terms_of_the_expression.get(index_of_the_base_term)).longValue());
		}

		/*And now add (or subtract) every other term*/
		for (int i=0;i<terms_of_the_expression.size();i++)
		{
			if (i==index_of_the_base_term)
			{
				continue;
			}
			String frida_code_for_this_term=create_frida_code_for_one_term(terms_of_the_expression.get(i));
			if (frida_code_for_this_term.equals(""))
			{
				return ""; //a term that we do not know how to translate, the whole expression is unusable
			}
			if (term_is_added.get(i).booleanValue())
			{
				frida_code+=".add("+frida_code_for_this_term+")";
			}
			else
			{
				frida_code+=".sub("+frida_code_for_this_term+")";
			}
		}

		return frida_code;
	}


	/*
	 * Splits an address expression into its signed terms. Consecutive signs are folded, so that the "RBP + -0x8" that
	 * Ghidra prints becomes a single term 0x8 which is subtracted, instead of an empty term between the two signs.
	 * Returns false if the expression cannot be split into at least one term.
	 */
	protected Boolean split_expression_into_signed_terms(String arg, ArrayList<String> terms_of_the_expression, ArrayList<Boolean> term_is_added)
	{
		String current_term="";
		Boolean next_term_is_added=true;

		for (int i=0;i<arg.length();i++)
		{
			char current_char=arg.charAt(i);
			if (current_char!='+' && current_char!='-')
			{
				current_term+=current_char; //the '*' of a scaled register is kept inside the term
				continue;
			}
			if (current_term.trim().equals(""))
			{
				//two signs in a row (or a sign at the very beginning), so this sign applies to the term that follows
				if (current_char=='-')
				{
					next_term_is_added=Boolean.valueOf(!next_term_is_added.booleanValue());
				}
				current_term="";
				continue;
			}
			terms_of_the_expression.add(current_term.trim());
			term_is_added.add(next_term_is_added);
			next_term_is_added=Boolean.valueOf(current_char=='+');
			current_term="";
		}
		if (!current_term.trim().equals(""))
		{
			terms_of_the_expression.add(current_term.trim());
			term_is_added.add(next_term_is_added);
		}

		return Boolean.valueOf(terms_of_the_expression.size()>0);
	}


	/*Translates a single term, which is either a register, a register multiplied by a scale, or a constant*/
	protected String create_frida_code_for_one_term(String term)
	{
		String register_of_term=return_frida_register_for_token(term);
		if (!register_of_term.equals(""))
		{
			return "this.context."+register_of_term;
		}

		Long value_of_term=return_value_of_constant_token(term);
		if (value_of_term!=null)
		{
			return return_hex_str_for_value(value_of_term.longValue());
		}

		if (term.indexOf("*")>=0)
		{
			String[] parts_of_term=term.split("\\*");
			if (parts_of_term.length==2)
			{
				String register_of_first_part=return_frida_register_for_token(parts_of_term[0]);
				Long value_of_second_part=return_value_of_constant_token(parts_of_term[1]);
				if (!register_of_first_part.equals("") && value_of_second_part!=null)
				{
					//the scale is a small number, so the index register can be handled as an integer
					return "this.context."+register_of_first_part+".toInt32()*"+return_hex_str_for_value(value_of_second_part.longValue());
				}
				String register_of_second_part=return_frida_register_for_token(parts_of_term[1]);
				Long value_of_first_part=return_value_of_constant_token(parts_of_term[0]);
				if (!register_of_second_part.equals("") && value_of_first_part!=null)
				{
					return "this.context."+register_of_second_part+".toInt32()*"+return_hex_str_for_value(value_of_first_part.longValue());
				}
			}
		}

		return "";
	}


	/*
	 * The destination of a RIP relative computed call is statically known, so it is calculated here.
	 * Careful: the displacement is relative to the address of the instruction that follows the current one.
	 */
	protected String create_frida_code_for_instruction_pointer_relative_expression(ArrayList<String> terms_of_the_expression,ArrayList<Boolean> term_is_added, Instruction incoming_instruction)
	{
		if (incoming_instruction==null)
		{
			return ""; //without the instruction we can neither know its address nor its length
		}

		long displacement=0;
		for (int i=0;i<terms_of_the_expression.size();i++)
		{
			String current_term=terms_of_the_expression.get(i);
			if (is_token_the_instruction_pointer(current_term))
			{
				if (!term_is_added.get(i).booleanValue())
				{
					return ""; //a subtracted instruction pointer is not a valid addressing form
				}
				continue;
			}
			Long value_of_term=return_value_of_constant_token(current_term);
			if (value_of_term==null)
			{
				//x86 does not allow another register together with RIP, so this is something we do not understand
				return "";
			}
			if (term_is_added.get(i).booleanValue())
			{
				displacement+=value_of_term.longValue();
			}
			else
			{
				displacement-=value_of_term.longValue();
			}
		}

		long address_of_the_next_instruction=incoming_instruction.getAddress().getOffset()+incoming_instruction.getLength();
		return create_frida_code_for_virtual_address(address_of_the_next_instruction+displacement);
	}


	/*
	 * Emits the frida code for an absolute virtual address, as an offset from the base of the module.
	 * Careful: this code ends up inside the body of a hook, so the module is looked up on every call through the hooked
	 * instruction. That is on purpose: every hook resolves the module on its own, so that it stays a self contained piece
	 * of code that can be copied out and pasted anywhere.
	 */
	protected String create_frida_code_for_virtual_address(long virtual_address)
	{
		long offset_from_the_image_base=virtual_address-this.incoming_program.getImageBase().getOffset();
		//OLD_API:"Module.findBaseAddress("+this.incoming_module_name_sanitized+")"
		String base_of_module="Process.getModuleByName("+this.incoming_module_name_sanitized+").base";
		/*The sign of an offset from the image base is decided in one single place for the whole plugin, so that a negative one can never end up being rendered as a huge unsigned hexadecimal*/
		return base_of_module+"."+HookGeneratorUtils.return_frida_operation_for_offset(offset_from_the_image_base)+"("+HookGeneratorUtils.return_hex_str_for_absolute_value_of_offset(offset_from_the_image_base)+")";
	}


	protected String return_hex_str_for_value(long value)
	{
		if (value<0)
		{
			return "-0x"+Long.toHexString(-value);
		}
		return "0x"+Long.toHexString(value);
	}


	/*Returns the value of a constant token, or null when the token is not a constant*/
	protected Long return_value_of_constant_token(String token)
	{
		if (token==null)
		{
			return null;
		}
		String token_to_examine=token.trim().toLowerCase();
		Boolean value_is_negative=false;
		if (token_to_examine.startsWith("-"))
		{
			value_is_negative=true;
			token_to_examine=token_to_examine.substring(1).trim();
		}
		try {
			long value;
			if (token_to_examine.startsWith("0x"))
			{
				value=Long.parseLong(token_to_examine.substring(2),16);
			}
			else
			{
				value=Long.parseLong(token_to_examine,10);
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


	protected Boolean is_token_the_instruction_pointer(String token)
	{
		if (token==null)
		{
			return false;
		}
		String token_to_examine=token.trim().toLowerCase();
		return Boolean.valueOf(token_to_examine.equals("rip") || token_to_examine.equals("eip"));
	}


	/*
	 * Returns the name of the frida CpuContext field for a register token, or the empty string when the token is not a
	 * register. Careful: the token has to be matched as a whole. The previous implementation was checking whether the
	 * token *contains* strings like "ax" or "ip", which made every token that happened to contain them be treated as a
	 * register.
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

		if (this.we_are_in_64bit_mode)
		{
			String[] registers_of_x64={"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15"};
			for (int i=0;i<registers_of_x64.length;i++)
			{
				if (token_to_examine.equals(registers_of_x64[i]))
				{
					return registers_of_x64[i];
				}
			}
			/*A 32 bit register can be used in an address expression through the address size prefix. The full register is used, which is an approximation, as the real address would be truncated to 32 bits*/
			String[] registers_of_x86={"eax","ebx","ecx","edx","esi","edi","ebp","esp"};
			String[] corresponding_registers_of_x64={"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp"};
			for (int i=0;i<registers_of_x86.length;i++)
			{
				if (token_to_examine.equals(registers_of_x86[i]))
				{
					return corresponding_registers_of_x64[i];
				}
			}
			for (int i=8;i<=15;i++)
			{
				if (token_to_examine.equals("r"+i+"d"))
				{
					return "r"+i;
				}
			}
			return "";
		}

		String[] registers_of_x86={"eax","ebx","ecx","edx","esi","edi","ebp","esp"};
		for (int i=0;i<registers_of_x86.length;i++)
		{
			if (token_to_examine.equals(registers_of_x86[i]))
			{
				return registers_of_x86[i];
			}
		}
		return "";
	}

}
