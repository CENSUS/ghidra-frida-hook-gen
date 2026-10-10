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

package fridahookgenerator;

import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;

/*
 * Everything that the calling convention of a function decides about the hook that is written for it.
 *
 * Two quite different things are decided here, and they are together because they are read out of the same place:
 *
 *  - the abi that an Interceptor.replace() is given. That form of hook builds a NativeFunction and a NativeCallback, and both
 *    of them accept an abi, so the convention can be handed to frida and frida does the rest.
 *
 *  - where an Interceptor.attach() reads each argument from. That form accepts no abi at all: the args[] of an onEnter are read
 *    the way the system passes arguments, which on 32 bit x86 means off the stack. A convention that passes the first arguments
 *    in registers therefore leaves them out of args[] altogether, and the only way to print them is to read the registers.
 *
 * Nothing here holds any state and nothing here writes a hook. Every function is given what it needs to decide and returns a
 * piece of text, so the whole of it can be run, and is run, by the level 0 checks of the self test without a program being open.
 *
 * Careful: the plugin wrote no abi and read every argument from args[<its position>] before any of this existed, and that is
 * what it still writes for a user who does not ask for otherwise. Every function below either is asked whether the option is on
 * or is called only after that has been asked, and the answer for a target where an abi is not a choice is the same as the
 * answer for the option being off.
 */
public class FridaAbiHandler {

	/*
	 * Whether this target is one where an abi is a choice at all, which is the same question as whether the names that Ghidra
	 * uses for the conventions mean there what frida means by them.
	 *
	 * Only 32 bit x86 has more than one abi that frida can be told about, and only the compiler spec of Visual Studio names the
	 * conventions the way frida does. Borland and Delphi use the same names for conventions they implement differently, and a
	 * stdcall of gcc on 32 bit is not something frida's documentation offers outside Windows.
	 */
	public static Boolean can_an_abi_be_chosen_for_this_target(String identifier_of_the_language,String identifier_of_the_compiler_spec)
	{
		if (identifier_of_the_language==null || identifier_of_the_compiler_spec==null)
		{
			return false;
		}
		return Boolean.valueOf(identifier_of_the_language.indexOf("x86:LE:32")>=0 && identifier_of_the_compiler_spec.equals("windows"));
	}

	/*
	 * The abi that has to be written into an Interceptor.replace() hook for a function, or an empty string when nothing has to
	 * be written and frida is left to use the one of the system.
	 *
	 * Careful, because two things make this narrower than it looks:
	 *
	 * The first is that frida has one abi for most targets. The abis it accepts are default, sysv, stdcall, thiscall, fastcall,
	 * mscdecl, win64, unix64 and vfp, and of those only the five of 32 bit x86 are a real choice: on 64 bit x86 the abi follows
	 * the operating system, which frida already knows, and AArch64 has one calling convention altogether. So there is nothing
	 * to say anywhere except on 32 bit x86.
	 *
	 * The second is that Ghidra uses the names __stdcall, __cdecl and __fastcall as labels for whatever the convention of the
	 * platform happens to be, and not only for the conventions of 32 bit Windows that carry those names. In the compiler spec
	 * of 64 bit Windows the three of them are aliases of one another, all meaning the one convention that the platform has, so
	 * a function reported there as __stdcall has nothing to do with the stdcall that frida means. Believing the name outside 32
	 * bit x86 would write an abi that is wrong rather than one that is missing.
	 *
	 * The compiler spec is asked for as well, and only the one of Visual Studio is accepted, because that is where these names
	 * mean what frida means by them. Borland and Delphi name their conventions the same way and do not implement them the same
	 * way, and a stdcall of gcc on 32 bit Linux is not something frida's documentation offers outside Windows.
	 *
	 * Anything that is not understood returns an empty string. Writing no abi is what the plugin did before this existed, so a
	 * name that is not in the table below costs nothing, whereas a name that is guessed costs a corrupted stack.
	 */
	public static String return_frida_abi_for_the_calling_convention(String name_of_the_calling_convention,String identifier_of_the_language,String identifier_of_the_compiler_spec)
	{
		if (name_of_the_calling_convention==null || identifier_of_the_language==null || identifier_of_the_compiler_spec==null)
		{
			return "";
		}
		if (!can_an_abi_be_chosen_for_this_target(identifier_of_the_language,identifier_of_the_compiler_spec).booleanValue())
		{
			return "";
		}
		String trimmed_name=name_of_the_calling_convention.trim();
		if (trimmed_name.equals("__stdcall")) { return "stdcall"; }
		if (trimmed_name.equals("__fastcall")) { return "fastcall"; }
		if (trimmed_name.equals("__thiscall")) { return "thiscall"; }
		/*
		 * Careful: __cdecl is deliberately not in the table. It is the abi that frida uses there when it is told nothing, so
		 * writing mscdecl for it would only add a word to every hook of every 32 bit Windows program. The same goes for
		 * __vectorcall and __regcall, which frida has no name for at all, and for unknown and default, which say nothing.
		 */
		return "";
	}

	/*
	 * What has to be said at the top of an Interceptor.attach() hook about the arguments it is about to print, or an empty string
	 * when there is nothing to say.
	 *
	 * Interceptor.attach(target, callbacks[, data]) takes no abi and there is no way to tell it a calling convention: the args[]
	 * of an onEnter() are read the way the system passes arguments, which on 32 bit x86 means off the stack. A convention that
	 * puts the first arguments in registers therefore does not appear in args[] at all, and the values printed for it are whatever
	 * happened to be on the stack.
	 *
	 * This is the fallback of the two comments, written for the hooks that could not be made right: the ones whose arguments this
	 * file could not place, and the ones that read no argument at all because they were asked for without an onEnter() or with the
	 * printing of the parameters switched off. Such a hook cannot be made right, so it is made honest instead, by saying which
	 * register holds what and that this.context is the way to read it. A hook that did read its arguments from the right places
	 * gets return_the_note_that_says_that_the_parameters_are_read_from_their_storage() instead, and never both.
	 *
	 * Careful: __stdcall is not reported here. It passes every argument on the stack exactly as __cdecl does, and the difference
	 * between them is only who cleans the stack afterwards, which does not concern a hook that merely watches the call.
	 */
	public static String return_the_warning_about_the_arguments_of_an_attach_hook(String name_of_the_calling_convention,String identifier_of_the_language,String identifier_of_the_compiler_spec)
	{
		if (name_of_the_calling_convention==null
				|| !can_an_abi_be_chosen_for_this_target(identifier_of_the_language,identifier_of_the_compiler_spec).booleanValue())
		{
			return "";
		}
		String trimmed_name=name_of_the_calling_convention.trim();
		if (trimmed_name.equals("__thiscall"))
		{
			return "//Careful: the database says this function is __thiscall, so its first argument is passed in ECX and is not in args[] at all."
					+" Read it with this.context.ecx , and count the arguments of args[] from the second one onwards."
					+" Interceptor.attach() cannot be told a calling convention, which is why this is a comment and not code";
		}
		if (trimmed_name.equals("__fastcall"))
		{
			return "//Careful: the database says this function is __fastcall, so its first two arguments are passed in ECX and EDX and are not in args[] at all."
					+" Read them with this.context.ecx and this.context.edx , and count the arguments of args[] from the third one onwards."
					+" Interceptor.attach() cannot be told a calling convention, which is why this is a comment and not code";
		}
		if (trimmed_name.equals("__vectorcall"))
		{
			return "//Careful: the database says this function is __vectorcall, which passes arguments in registers, so the ones it passes that way are not in args[] at all."
					+" Read them through this.context . Interceptor.attach() cannot be told a calling convention, which is why this is a comment and not code";
		}
		return "";
	}

	/*
	 * What has to be said at the top of an Interceptor.attach() hook whose arguments are read from where the calling convention
	 * puts them instead of from args[].
	 *
	 * This is the counterpart of return_the_warning_about_the_arguments_of_an_attach_hook(): that one is written when the hook
	 * cannot be made right and the reader has to do the work by hand, this one when the hook has already done it. Only one of the
	 * two is ever written into the same hook.
	 */
	public static String return_the_note_that_says_that_the_parameters_are_read_from_their_storage(String name_of_the_calling_convention,String[] javascript_that_reads_each_parameter,String identifier_of_the_language,String identifier_of_the_compiler_spec)
	{
		if (!can_an_abi_be_chosen_for_this_target(identifier_of_the_language,identifier_of_the_compiler_spec).booleanValue())
		{
			return "";
		}
		/*
		 * Careful: the registers are taken from what the hook really reads and not from the name of the convention. A __fastcall
		 * function with a single argument has only ECX to read, so a sentence written from the name alone would promise a read of
		 * EDX that is nowhere in the hook, and a convention with storage that somebody set by hand would be described by the
		 * registers its name usually uses rather than by the ones it has.
		 */
		String the_registers=return_the_registers_that_the_arguments_are_read_from(javascript_that_reads_each_parameter);
		if (the_registers.equals(""))
		{
			/*Nothing was read out of a register, so this hook has nothing to say for itself and the caller falls back to the warning*/
			return "";
		}
		String trimmed_name=(name_of_the_calling_convention==null)?"":name_of_the_calling_convention.trim();
		String what_the_function_is;
		if (trimmed_name.equals("") || trimmed_name.equals("unknown") || trimmed_name.equals("default"))
		{
			what_the_function_is="//The database places some of the arguments of this function in registers";
		}
		else
		{
			what_the_function_is="//The database says this function is "+return_the_name_of_a_calling_convention_made_safe_for_a_comment(trimmed_name)
					+" , which passes some of its arguments in registers";
		}
		/*
		 * Careful: the last clause is only true when there is an argument left for args[] to carry. A __thiscall function of one
		 * argument has all of it in ECX, and sending the reader off to args[] for the rest of something that has no rest is the same
		 * kind of promise as naming a register the hook never read.
		 */
		boolean an_argument_is_read_from_the_array=false;
		for (int i=0;i<javascript_that_reads_each_parameter.length;i++)
		{
			if (javascript_that_reads_each_parameter[i]!=null && !javascript_that_reads_each_parameter[i].startsWith("this.context."))
			{
				an_argument_is_read_from_the_array=true;
			}
		}
		return what_the_function_is+", so those are not in args[] at all."
				+" They are read below from "+the_registers
				+(an_argument_is_read_from_the_array
						?" , and every argument after them from the args[] that really carries it"
						:" , and this function passes no argument anywhere else");
	}

	/*
	 * The registers that the arguments of a hook are really read out of, written as the javascript that reads them and joined the
	 * way a sentence joins them, or an empty string when no argument of the hook is read out of a register at all.
	 */
	public static String return_the_registers_that_the_arguments_are_read_from(String[] javascript_that_reads_each_parameter)
	{
		if (javascript_that_reads_each_parameter==null)
		{
			return "";
		}
		String retval="";
		String the_one_before_the_last="";
		for (int i=0;i<javascript_that_reads_each_parameter.length;i++)
		{
			if (javascript_that_reads_each_parameter[i]==null || !javascript_that_reads_each_parameter[i].startsWith("this.context."))
			{
				continue;
			}
			if (the_one_before_the_last.equals(""))
			{
				the_one_before_the_last=javascript_that_reads_each_parameter[i];
				continue;
			}
			retval=retval.equals("")?the_one_before_the_last:(retval+", "+the_one_before_the_last);
			the_one_before_the_last=javascript_that_reads_each_parameter[i];
		}
		if (the_one_before_the_last.equals(""))
		{
			return "";
		}
		return retval.equals("")?the_one_before_the_last:(retval+" and "+the_one_before_the_last);
	}

	/*
	 * The javascript that reads a register of a 32 bit x86 process out of the context of a hook, or an empty string for a name that
	 * the context of frida does not carry.
	 */
	public static String return_the_javascript_that_reads_a_register_of_a_32_bit_x86_process(String name_of_the_register)
	{
		if (name_of_the_register==null)
		{
			return "";
		}
		String name_in_lowercase=name_of_the_register.trim().toLowerCase();
		/*The registers that the CpuContext of frida carries for a 32 bit x86 process, and nothing else*/
		if (name_in_lowercase.equals("eax") || name_in_lowercase.equals("ecx") || name_in_lowercase.equals("edx")
				|| name_in_lowercase.equals("ebx") || name_in_lowercase.equals("esp") || name_in_lowercase.equals("ebp")
				|| name_in_lowercase.equals("esi") || name_in_lowercase.equals("edi") || name_in_lowercase.equals("eip"))
		{
			return "this.context."+name_in_lowercase;
		}
		/*
		 * The narrower names of the same registers. A parameter of one or two bytes is given the name of the part that holds it,
		 * such as CL or CX, and the context of frida carries only the whole register. Reading the whole one is right for every name
		 * below, because the value sits in its lowest bytes exactly as the machine passed it, and a reader who sees ecx printed for
		 * an argument declared as a char has the byte in front of them.
		 *
		 * Careful: ah, bh, ch and dh are deliberately not here, although they are parts of the very same four registers. The value
		 * of a parameter that lives in one of those does not sit in the low bytes of the whole register, so reading the whole one
		 * would print a different byte altogether. They return nothing, and nothing is what makes the caller leave that function's
		 * arguments where they always were and say so in a comment.
		 */
		if (name_in_lowercase.equals("al") || name_in_lowercase.equals("ax")) { return "this.context.eax"; }
		if (name_in_lowercase.equals("cl") || name_in_lowercase.equals("cx")) { return "this.context.ecx"; }
		if (name_in_lowercase.equals("dl") || name_in_lowercase.equals("dx")) { return "this.context.edx"; }
		if (name_in_lowercase.equals("bl") || name_in_lowercase.equals("bx")) { return "this.context.ebx"; }
		if (name_in_lowercase.equals("si")) { return "this.context.esi"; }
		if (name_in_lowercase.equals("di")) { return "this.context.edi"; }
		return "";
	}

	/*
	 * Which args[] of frida carries the argument that the database places at the given offset of the stack, or -1 when that offset
	 * is not one that an argument of a 32 bit x86 call sits at.
	 *
	 * At the entry of a function the stack carries the return address, and the arguments follow it. Ghidra counts the offsets of
	 * the parameters from that very same point, so the first argument is at offset 4 and frida calls it args[0].
	 *
	 * This is not a guess about frida. Its gum_cpu_context_get_nth_argument(), in gum/backend-x86/gumcpucontext-x86.c , answers a
	 * 32 bit process with
	 *
	 *     stack_argument = (gpointer *) (self->esp + 4);
	 *     return stack_argument[n];
	 *
	 * so args[n] is the word at esp+4+4*n and nothing else: the 4 steps over the return address, and the indexing steps a word at
	 * a time. The branches of that same function for 64 bit processes do read registers first, rdi rsi rdx rcx r8 r9 on the system
	 * of unix and rcx rdx r8 r9 on the one of windows, but the branch for 32 bit has no register in it at all, which is what makes
	 * an argument that a convention puts in ECX or EDX invisible to args[] and every argument behind it sit one place lower.
	 */
	public static int return_the_index_of_the_argument_of_frida_for_a_stack_offset(int offset_in_the_stack)
	{
		if (offset_in_the_stack<4 || (offset_in_the_stack%4)!=0)
		{
			return -1;
		}
		return (offset_in_the_stack-4)/4;
	}

	/*
	 * The whole of what a hook prints in front of the value of one argument.
	 *
	 * While every argument is read from the position it occupies, the index of the args[] is the number of the argument and there
	 * is nothing else to say: args[0] is the first one. That is what this plugin has always printed and it is what it still prints.
	 *
	 * The moment an argument is read from somewhere else, that stops being true and the number has to be said out loud, because an
	 * argument in ECX carries no index at all and the one after it is read from args[0] although it is the second argument of the
	 * function. So such an argument is printed as arg_0, arg_1 and so on, which is the same way the callback of a replacement names
	 * its own parameters.
	 *
	 * A register is named in brackets beside the number, because that is the one extra thing a reader wants: it is what they write
	 * to if they mean to change the value. An index of args[] is not named there. It says nothing a reader can use, and printing
	 * args[0] beside arg_1 puts the two numbers that have to be kept apart right next to each other, which is the very thing the
	 * number was added to prevent. Where the arguments come from is said once, in the comment at the top of the hook.
	 */
	public static String return_the_label_that_a_hook_prints_in_front_of_a_parameter(int position_of_the_parameter,
			String javascript_that_reads_the_parameter,String name_of_the_parameter_or_an_empty_string)
	{
		String javascript=(javascript_that_reads_the_parameter==null)?"":javascript_that_reads_the_parameter;
		String name=(name_of_the_parameter_or_an_empty_string==null)?"":name_of_the_parameter_or_an_empty_string;
		String what_it_would_be_read_as_from_its_own_position="args["+position_of_the_parameter+"]";

		/*Nothing to read means nothing to explain, so the label falls back to the one the argument has always had*/
		String label="arg_"+position_of_the_parameter;
		if (javascript.equals("") || javascript.equals(what_it_would_be_read_as_from_its_own_position))
		{
			label=what_it_would_be_read_as_from_its_own_position;
		}

		String what_goes_in_the_brackets="";
		if (javascript.startsWith("this.context."))
		{
			what_goes_in_the_brackets=javascript.substring("this.context.".length());
		}
		if (!name.equals(""))
		{
			what_goes_in_the_brackets=what_goes_in_the_brackets.equals("")?name:(what_goes_in_the_brackets+", "+name);
		}
		if (what_goes_in_the_brackets.equals(""))
		{
			return label;
		}
		return label+"("+what_goes_in_the_brackets+")";
	}

	/*
	 * The javascript that reads one parameter of a 32 bit x86 process from the place the database gives it, or an empty string when
	 * that place is not one a hook can read.
	 *
	 * Careful: only a storage made of a single piece is understood. A parameter that the database spreads over two registers, or
	 * over a register and the stack, returns an empty string for the caller to refuse, because reading half of such a parameter
	 * would be worse than not reading it.
	 */
	public static String return_the_javascript_that_reads_the_storage_of_a_parameter(VariableStorage storage_of_the_parameter)
	{
		if (storage_of_the_parameter==null)
		{
			return "";
		}
		/*
		 * The storage has to be a single piece. A parameter spread over two of them, such as a 64 bit value in a pair of registers,
		 * would otherwise be asked for its first register alone and half of it would be printed as if it were the whole.
		 */
		if (storage_of_the_parameter.getVarnodes()==null || storage_of_the_parameter.getVarnodes().length!=1)
		{
			return "";
		}
		if (storage_of_the_parameter.isRegisterStorage())
		{
			Register register_that_carries_it=storage_of_the_parameter.getRegister();
			if (register_that_carries_it==null)
			{
				return "";
			}
			/*
			 * The name is passed on as the database gives it, the narrow names included, and which of them can be read as a whole
			 * register is decided in one place below.
			 *
			 * Careful: the parent register is deliberately not asked for here. The parent of AH is EAX, so asking would turn a
			 * parameter that lives in the second byte of EAX into a read of the whole of it, and the value printed would be the
			 * wrong byte. The table below knows which narrow names sit at the bottom of their register and which do not.
			 */
			return return_the_javascript_that_reads_a_register_of_a_32_bit_x86_process(register_that_carries_it.getName());
		}
		if (storage_of_the_parameter.isStackStorage())
		{
			int index_of_the_argument=return_the_index_of_the_argument_of_frida_for_a_stack_offset(storage_of_the_parameter.getStackOffset());
			if (index_of_the_argument<0)
			{
				return "";
			}
			return "args["+index_of_the_argument+"]";
		}
		return "";
	}

	/*
	 * Where each parameter of a function is read from inside an onEnter(), one entry per parameter, in the order the database has
	 * them. An entry is either an args[] of frida or a register of this.context.
	 *
	 * With the option off, and on every target where an abi is not a choice at all, every entry is args[<position of the
	 * parameter>], which is the form this plugin has always written. Nothing that calls this has to know whether the option is on:
	 * it says whether the user asked for it, takes the text and writes back whatever came.
	 *
	 * Careful: this is all or nothing on purpose. A convention that passes the first arguments in registers leaves every argument
	 * after them at an index of args[] smaller than its own position, so placing some parameters and leaving the rest at
	 * args[<position>] would print, for those left behind, the value of a different parameter altogether. If even one parameter
	 * cannot be placed, all of them stay as they were and the comment at the top of the hook tells the reader what to do by hand.
	 */
	public static String[] return_the_javascript_that_reads_each_parameter(Function current_function,int parameter_count,
			Boolean the_user_asked_for_the_calling_convention_to_be_used,String identifier_of_the_language,String identifier_of_the_compiler_spec)
	{
		String[] the_standard_way=new String[parameter_count>0?parameter_count:0];
		for (int i=0;i<the_standard_way.length;i++)
		{
			the_standard_way[i]="args["+i+"]";
		}
		if (the_standard_way.length==0 || current_function==null
				|| the_user_asked_for_the_calling_convention_to_be_used==null
				|| !the_user_asked_for_the_calling_convention_to_be_used.booleanValue())
		{
			return the_standard_way;
		}
		if (!can_an_abi_be_chosen_for_this_target(identifier_of_the_language,identifier_of_the_compiler_spec).booleanValue())
		{
			return the_standard_way;
		}

		String[] the_way_the_storage_asks_for=new String[the_standard_way.length];
		for (int i=0;i<the_way_the_storage_asks_for.length;i++)
		{
			Parameter parameter_of_the_function=current_function.getParameter(i);
			if (parameter_of_the_function==null)
			{
				return the_standard_way;
			}
			the_way_the_storage_asks_for[i]=return_the_javascript_that_reads_the_storage_of_a_parameter(parameter_of_the_function.getVariableStorage());
			if (the_way_the_storage_asks_for[i].equals(""))
			{
				return the_standard_way;
			}
		}
		/*Two parameters read from the very same place would mean that the storage was not understood, whatever it said*/
		for (int i=0;i<the_way_the_storage_asks_for.length;i++)
		{
			for (int j=i+1;j<the_way_the_storage_asks_for.length;j++)
			{
				if (the_way_the_storage_asks_for[i].equals(the_way_the_storage_asks_for[j]))
				{
					return the_standard_way;
				}
			}
		}
		return the_way_the_storage_asks_for;
	}

	/*
	 * What has to be said in the hook when no abi is written into it, or an empty string when there is nothing worth saying.
	 *
	 * An empty abi has three quite different causes and they must not be described with one sentence:
	 *
	 *  - the database has no convention for the function at all. On a target where an abi could have been chosen that is worth
	 *    saying, because the decompiler shows a convention for such a function anyway, worked out from the registers it saw, and
	 *    somebody who reads that and then finds no abi in the hook cannot tell whether the plugin ignored it or never had it.
	 *
	 *  - the convention is __cdecl on 32 bit Windows, which is the abi frida uses when it is told nothing. Nothing is lost and
	 *    nothing has to be said, or every hook of every such program would carry a line about a choice that was already right.
	 *
	 *  - frida has no abi for the convention. The replacement is still written, because a hook with the abi of the system is
	 *    worth more than no hook at all, but an argument that the convention passes somewhere else is read from the wrong place,
	 *    and that is the one case here where the generated code may be wrong rather than merely unspecific.
	 *
	 * Careful with the third one: only the names that are never an alias of the convention of their platform are reported. Ghidra
	 * uses __stdcall as the name of the default model on 32 bit Linux and as an alias of the single convention of 64 bit Windows,
	 * so reporting every name that this file does not map would put a warning on nearly every function of those programs.
	 */
	public static String return_the_reason_why_no_abi_is_written(String name_of_the_calling_convention,String identifier_of_the_language,String identifier_of_the_compiler_spec)
	{
		if (!return_frida_abi_for_the_calling_convention(name_of_the_calling_convention,identifier_of_the_language,identifier_of_the_compiler_spec).equals(""))
		{
			return "";	//an abi is written, so there is nothing to explain
		}
		String trimmed_name="";
		if (name_of_the_calling_convention!=null)
		{
			trimmed_name=name_of_the_calling_convention.trim();
		}

		/*The conventions that no platform uses as the name of its default, and that frida cannot express either*/
		if (trimmed_name.equals("__vectorcall") || trimmed_name.equals("__regcall"))
		{
			return "//No abi is written for this replacement, because frida has no abi for the calling convention "+trimmed_name
					+" that the database gives this function. The replacement is still installed and uses the abi of the system, so an argument that "
					+trimmed_name+" passes somewhere else is read from the wrong place";
		}

		if (!can_an_abi_be_chosen_for_this_target(identifier_of_the_language,identifier_of_the_compiler_spec).booleanValue())
		{
			return "";	//nothing could have been chosen here in any case
		}
		if (trimmed_name.equals("") || trimmed_name.equals("unknown") || trimmed_name.equals("default"))
		{
			return "//No abi is written for this replacement, because the database has no calling convention for this function."
					+" On this target one could be chosen, so run Analysis -> Decompiler Parameter ID to have Ghidra work the conventions out, and regenerate";
		}
		if (trimmed_name.equals("__cdecl"))
		{
			return "";	//the abi that frida uses when it is told nothing, so writing it would say the same thing at greater length
		}
		/*
		 * Careful: the name is made safe here and not above. The branch above is reached only by a name that is exactly __vectorcall
		 * or __regcall, so there is nothing in it to make safe, whereas this one is reached by whatever the database happens to
		 * hold.
		 */
		String name_that_is_safe_to_write=return_the_name_of_a_calling_convention_made_safe_for_a_comment(trimmed_name);
		return "//No abi is written for this replacement, because frida has no abi for the calling convention "+name_that_is_safe_to_write
				+" that the database gives this function. The replacement is still installed and uses the abi of the system, so an argument that "
				+name_that_is_safe_to_write+" passes somewhere else is read from the wrong place";
	}

	/*
	 * The name of a calling convention, made safe to put inside a line comment of the generated script.
	 *
	 * Careful: the name comes out of the compiler spec of the database and is written into a comment that begins with // . A name
	 * carrying a carriage return or a line feed would end that comment where it sits and leave the rest of the sentence behind as
	 * javascript, which is how a name in a database becomes code in a script. Everything that is not a letter, a digit or an
	 * underscore is therefore taken out of it, and nothing readable is lost by that: every convention that Ghidra ships is written
	 * with those characters alone.
	 */
	public static String return_the_name_of_a_calling_convention_made_safe_for_a_comment(String name_of_the_calling_convention)
	{
		if (name_of_the_calling_convention==null)
		{
			return "";
		}
		return name_of_the_calling_convention.trim().replaceAll("[^0-9a-zA-Z_]","_");
	}

	/*================================================================================================================
	 * What the generator asks for.
	 *
	 * Everything above decides one thing each and is given exactly what it needs to decide it, which is what lets the level 0
	 * checks drive all of it with nothing open. The four below are the whole of what the generator calls: it hands over the
	 * function, the program and the answer to the one question that is its own, whether the user asked for this at all, and gets
	 * back a piece of text to write or an empty string to write nothing.
	 *
	 * Careful: no decision of this file belongs on the other side of this line. A generator that had to ask whether an abi was
	 * written before deciding which comment to write, or had to put the quotes and the comma around an abi itself, would be a
	 * second place where the rules live, and the two places would come to disagree the way two such places always do.
	 *================================================================================================================*/

	/*The two things that say which conventions a program can have. An unreadable program answers with nothing, which no target matches*/
	public static String return_the_identifier_of_the_language_of(Program current_program)
	{
		if (current_program==null || current_program.getLanguage()==null)
		{
			return "";
		}
		return current_program.getLanguage().getLanguageID().toString();
	}

	public static String return_the_identifier_of_the_compiler_spec_of(Program current_program)
	{
		if (current_program==null || current_program.getCompilerSpec()==null)
		{
			return "";
		}
		return current_program.getCompilerSpec().getCompilerSpecID().getIdAsString();
	}

	/*Whether this program is one where an abi is a choice at all, which is what decides whether the option is worth offering*/
	public static Boolean can_an_abi_be_chosen_for_this_target(Program current_program)
	{
		return can_an_abi_be_chosen_for_this_target(return_the_identifier_of_the_language_of(current_program),
				return_the_identifier_of_the_compiler_spec_of(current_program));
	}

	/*Where each parameter of a function is read from inside an onEnter(), asked with the program as the generator holds it*/
	public static String[] return_the_javascript_that_reads_each_parameter(Function current_function,int parameter_count,
			Boolean the_user_asked_for_the_calling_convention_to_be_used,Program current_program)
	{
		return return_the_javascript_that_reads_each_parameter(current_function,parameter_count,
				the_user_asked_for_the_calling_convention_to_be_used,
				return_the_identifier_of_the_language_of(current_program),
				return_the_identifier_of_the_compiler_spec_of(current_program));
	}

	/*
	 * The text that carries the abi into an Interceptor.replace(), ready to be written where it goes, or an empty string when no
	 * abi is written. The comma and the quotes are put here and not by the caller, so that the shape of an abi is written down in
	 * one place.
	 */
	public static String return_the_text_of_the_abi_for_a_replacement(Function current_function,
			Boolean the_user_asked_for_the_calling_convention_to_be_used,Program current_program)
	{
		if (current_function==null || the_user_asked_for_the_calling_convention_to_be_used==null
				|| !the_user_asked_for_the_calling_convention_to_be_used.booleanValue())
		{
			return "";
		}
		String name_of_the_abi=return_frida_abi_for_the_calling_convention(current_function.getCallingConventionName(),
				return_the_identifier_of_the_language_of(current_program),
				return_the_identifier_of_the_compiler_spec_of(current_program));
		if (name_of_the_abi.equals(""))
		{
			return "";
		}
		return ",'"+name_of_the_abi+"'";
	}

	/*
	 * The comment that an Interceptor.replace() carries about its abi, or an empty string when there is nothing worth saying.
	 * Whether an abi was written is worked out here rather than asked of the caller, because it is the same question that decides
	 * the text above and the two answers must never differ.
	 */
	public static String return_the_comment_about_the_abi_of_a_replacement(Function current_function,
			Boolean the_user_asked_for_the_calling_convention_to_be_used,Program current_program)
	{
		if (current_function==null || the_user_asked_for_the_calling_convention_to_be_used==null
				|| !the_user_asked_for_the_calling_convention_to_be_used.booleanValue())
		{
			return "";
		}
		return return_the_reason_why_no_abi_is_written(current_function.getCallingConventionName(),
				return_the_identifier_of_the_language_of(current_program),
				return_the_identifier_of_the_compiler_spec_of(current_program));
	}

	/*
	 * The comment that an Interceptor.attach() carries about its arguments, or an empty string when there is nothing to say.
	 *
	 * There are two such comments and only one of them is ever written. The note is the one for a hook that read its arguments out
	 * of the places the convention puts them, and it answers with nothing when this hook did not, which is what leaves the warning
	 * that tells the reader to do it by hand. The caller says only whether the hook reads its arguments at all, because that is a
	 * question about the options of the hook and not about the calling convention of anything.
	 */
	public static String return_the_comment_about_the_arguments_of_an_attach_hook(Function current_function,
			String[] javascript_that_reads_each_parameter,Boolean the_hook_reads_its_parameters,
			Boolean the_user_asked_for_the_calling_convention_to_be_used,Program current_program)
	{
		if (current_function==null || the_user_asked_for_the_calling_convention_to_be_used==null
				|| !the_user_asked_for_the_calling_convention_to_be_used.booleanValue())
		{
			return "";
		}
		String identifier_of_the_language=return_the_identifier_of_the_language_of(current_program);
		String identifier_of_the_compiler_spec=return_the_identifier_of_the_compiler_spec_of(current_program);
		if (the_hook_reads_its_parameters!=null && the_hook_reads_its_parameters.booleanValue())
		{
			String the_note=return_the_note_that_says_that_the_parameters_are_read_from_their_storage(
					current_function.getCallingConventionName(),javascript_that_reads_each_parameter,
					identifier_of_the_language,identifier_of_the_compiler_spec);
			if (!the_note.equals(""))
			{
				return the_note;
			}
		}
		return return_the_warning_about_the_arguments_of_an_attach_hook(current_function.getCallingConventionName(),
				identifier_of_the_language,identifier_of_the_compiler_spec);
	}
}
