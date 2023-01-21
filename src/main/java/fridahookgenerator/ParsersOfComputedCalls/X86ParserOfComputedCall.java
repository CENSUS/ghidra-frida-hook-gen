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

import docking.action.KeyBindingType;
import fridahookgenerator.ParserOfComputedCalls;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

/*This class tries to decode the argument to CALL <arg> in x86, and translate them into frida code*/
public class X86ParserOfComputedCall implements ParserOfComputedCalls{

	private Program incoming_program;
	private Language current_program_language;
	private Processor current_program_processor;
	private String incoming_module_name_sanitized;
	
	public X86ParserOfComputedCall(Program incoming_program, String incoming_module_name_sanitized) {
		this.incoming_program=incoming_program;
		this.current_program_language = this.incoming_program.getLanguage();
		this.current_program_processor = this.current_program_language.getProcessor();
		this.incoming_module_name_sanitized=incoming_module_name_sanitized;
	}
	
	
	public String create_frida_code_for_call_arg(String mnemonic,String arg)
	{
		String retval="";
		Boolean is_ptr_dereference=false;
		Boolean arg_is_a_number=false;
		if (arg=="")
		{
			return "";
		}
		arg=arg.replaceAll(".?word ptr","").trim();
		if (arg.charAt(0)=='[' && arg.charAt(arg.length()-1)==']')
		{
			is_ptr_dereference=true;
			arg=arg.substring(1, arg.length()-1); //Strip the dereference brackets and continue
			if (!arg.matches("[0-9a-zA-Z\\+\\*\\-\\ ]*")) //Allowed characters
			{
				return "";
			}
		}
		
		/*Check if arg is simply a hex number*/
		try {
			if (arg.strip().matches("^0x[a-fA-F0-9]+$"))
			{
				long tmplong=Long.parseLong(arg.substring(2),16);
				arg_is_a_number=true;
			}
		}
		catch (NumberFormatException ex)
		{
			arg_is_a_number=false;
		}

		if (arg_is_a_number)
		{
			/*Simply number, maybe in a dereference. No complex parsing needed*/
			retval+="Module.findBaseAddress("+this.incoming_module_name_sanitized+").add("+arg+")";
		}
		else
		{
			/*Do the parsing of the command */
			ArrayList<String> substrings_with_registers=new ArrayList<String>();
			String str_so_far="";
			for (int i=0;i<arg.length();i++)
			{
				if (arg.charAt(i)=='+' || arg.charAt(i)=='-' || arg.charAt(i)=='*' || i==arg.length()-1)
				{
					if (i==arg.length()-1 && arg.charAt(i)!='+' && arg.charAt(i)!='-' && arg.charAt(i)!='*')
					{
						//append
						str_so_far+=arg.charAt(i);
					}
					//create new entry in the arraylist
					substrings_with_registers.add(str_so_far);
					str_so_far=""; //reset
					if (arg.charAt(i)=='+' || arg.charAt(i)=='-' || arg.charAt(i)=='*')
					{
						substrings_with_registers.add(""+arg.charAt(i));
					}
				}
				else
				{
					//just append the character
					str_so_far+=arg.charAt(i);
				}
			}
			
			// Now try to construct the frida code
			int add_parentheses_because_of_previous_addition_or_subtraction=0; 
			for (int i=0;i<substrings_with_registers.size();i++)
			{
				if (substrings_with_registers.get(i).strip().equals("+"))
				{
					if (add_parentheses_because_of_previous_addition_or_subtraction>0)
					{
						//set the previous parentheses if any (created by previous additions or subtractions, but not inserted when encountering multiplication or a register)
						for (int j=0;j<add_parentheses_because_of_previous_addition_or_subtraction;j++)
						{
							retval+=")";
						}
						add_parentheses_because_of_previous_addition_or_subtraction=0;
					}
					
					retval+=".add(";
					add_parentheses_because_of_previous_addition_or_subtraction++;
				}
				else if (substrings_with_registers.get(i).strip().equals("-"))
				{
					
					if (add_parentheses_because_of_previous_addition_or_subtraction>0)
					{
						//set the previous parentheses if any (created by previous additions or subtractions, but not inserted when encountering multiplication or a register)
						for (int j=0;j<add_parentheses_because_of_previous_addition_or_subtraction;j++)
						{
							retval+=")";
						}
						add_parentheses_because_of_previous_addition_or_subtraction=0;
					}
					
					
					retval+=".sub(";
					add_parentheses_because_of_previous_addition_or_subtraction++;
				}
				else if (substrings_with_registers.get(i).strip().equals("*"))
				{
					retval+=".toInt32()*";  //if multiplies, it should be a small number
				}
				else
				{
					retval+=return_frida_register_if_str_is_register(substrings_with_registers.get(i).strip());
				}

			}
			//and set the remaining parentheses
			for (int i=0;i<add_parentheses_because_of_previous_addition_or_subtraction;i++)
			{
				retval+=")";
			}

		}
		
		retval="("+retval+")";
		if (is_ptr_dereference)
		{
			retval+=".readPointer()";
		}
		
		return retval;
	}
	
	
	private String return_frida_register_if_str_is_register(String in_str)
	{
		String retval="";
		in_str=in_str.toLowerCase();
		if (this.current_program_language.getLanguageID().toString().indexOf("x86:LE:64")>=0)
		{
			//case for x64
			if (in_str.indexOf("ax")>=0) retval="rax";
			if (in_str.indexOf("bx")>=0) retval="rbx";
			if (in_str.indexOf("cx")>=0) retval="rcx";
			if (in_str.indexOf("dx")>=0) retval="rdx";
			if (in_str.indexOf("si")>=0) retval="rsi";
			if (in_str.indexOf("di")>=0) retval="rdi";
			if (in_str.indexOf("sp")>=0) retval="sp";
			if (in_str.indexOf("bp")>=0) retval="rbp";
			if (in_str.indexOf("ip")>=0) retval="pc";
			if (in_str.indexOf("r8")>=0) retval="r8";
			if (in_str.indexOf("r9")>=0) retval="r9";
			if (in_str.indexOf("r10")>=0) retval="r10";
			if (in_str.indexOf("r11")>=0) retval="r11";
			if (in_str.indexOf("r12")>=0) retval="r12";
			if (in_str.indexOf("r13")>=0) retval="r13";
			if (in_str.indexOf("r14")>=0) retval="r14";
			if (in_str.indexOf("r15")>=0) retval="r15";
			if (in_str.indexOf("r16")>=0) retval="r16";
			if (in_str.indexOf("flags")>=0) retval="rflags";  //what sorcery is this
		}
		if (this.current_program_language.getLanguageID().toString().indexOf("x86:LE:32")>=0)
		{
			//case for x86, not ready yet. CALL far?
			if (in_str.indexOf("ax")>=0) retval="eax";
			if (in_str.indexOf("bx")>=0) retval="ebx";
			if (in_str.indexOf("cx")>=0) retval="ecx";
			if (in_str.indexOf("dx")>=0) retval="edx";
			if (in_str.indexOf("si")>=0) retval="esi";
			if (in_str.indexOf("di")>=0) retval="edi";
			if (in_str.indexOf("sp")>=0) retval="sp";
			if (in_str.indexOf("bp")>=0) retval="ebp";
			if (in_str.indexOf("ip")>=0) retval="pc";
			if (in_str.indexOf("flags")>=0) retval="eflags";  //If the code really does "call flags" flip table
		}
		
		if (retval=="")
		{
			//no substitution, probably a the in_str is a number
			retval=in_str;
		}
		else
		{
			retval="this.context."+retval;
		}
		return retval;
	}
	
}
