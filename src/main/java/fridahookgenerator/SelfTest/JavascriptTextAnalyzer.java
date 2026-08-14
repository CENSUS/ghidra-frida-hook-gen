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

/*
 * A small, deliberately simple reader of the generated javascript. It is NOT a javascript parser and it does not try to
 * be one: it knows just enough about the shape of the language to let the checks ask real questions instead of guessing
 * with regular expressions over the raw text.
 *
 * The one trick that everything else is built on: a second copy of the text is kept, in which every comment and every
 * string literal has been replaced by spaces, character for character. That copy has exactly the same length as the
 * original, so a position in it is a position in the original, and line numbers stay correct. Searching that copy finds
 * only real code, so a check for "Interceptor.attach(" does not match the same words inside a comment, and a check that
 * counts braces does not count the ones inside the strings of the generated console.log() calls.
 *
 * Careful: the scope model is intentionally flat. Every name that is declared anywhere is considered declared
 * everywhere. That direction is the safe one for a self test: it can miss a problem, but it will not invent one.
 */
public class JavascriptTextAnalyzer {

	protected String original_text;
	protected String code_only_text;	//same length as the original, with comments and strings blanked out
	protected ArrayList<Integer> position_where_every_line_starts;

	public JavascriptTextAnalyzer(String incoming_text)
	{
		if (incoming_text==null)
		{
			incoming_text="";
		}
		this.original_text=incoming_text;
		this.code_only_text=build_the_text_without_the_comments_and_the_strings(incoming_text);
		this.position_where_every_line_starts=build_the_index_of_the_lines(incoming_text);
	}

	/*
	 * Walks the text once and blanks out everything that is not code. Handles // comments, block comments, single quoted
	 * strings, double quoted strings and template literals, and the backslash escapes inside all of them.
	 */
	protected String build_the_text_without_the_comments_and_the_strings(String text)
	{
		char[] result=text.toCharArray();
		int i=0;
		int length_of_text=text.length();
		while (i<length_of_text)
		{
			char current_char=text.charAt(i);
			char next_char=' ';
			if (i+1<length_of_text)
			{
				next_char=text.charAt(i+1);
			}

			if (current_char=='/' && next_char=='/')
			{
				while (i<length_of_text && text.charAt(i)!='\n')
				{
					result[i]=' ';
					i++;
				}
				continue;
			}
			if (current_char=='/' && next_char=='*')
			{
				result[i]=' ';
				result[i+1]=' ';
				i+=2;
				while (i<length_of_text)
				{
					if (text.charAt(i)=='*' && i+1<length_of_text && text.charAt(i+1)=='/')
					{
						result[i]=' ';
						result[i+1]=' ';
						i+=2;
						break;
					}
					if (text.charAt(i)!='\n')
					{
						result[i]=' ';
					}
					i++;
				}
				continue;
			}
			if (current_char=='\"' || current_char=='\'' || current_char=='`')
			{
				char the_quote_that_opened=current_char;
				/*
				 * Careful: the two quotes themselves are kept and only what is between them is blanked out. If the quotes
				 * went away as well, then a perfectly ordinary "var name='something';" would look like an assignment with
				 * nothing on its right hand side, and the check that looks for exactly that would report every string of
				 * the generated script.
				 */
				i++;
				while (i<length_of_text)
				{
					char char_inside_the_string=text.charAt(i);
					if (char_inside_the_string=='\\')
					{
						result[i]=' ';
						if (i+1<length_of_text)
						{
							if (text.charAt(i+1)!='\n')
							{
								result[i+1]=' ';
							}
						}
						i+=2;
						continue;
					}
					if (char_inside_the_string==the_quote_that_opened)
					{
						i++;
						break;
					}
					if (char_inside_the_string!='\n')
					{
						result[i]=' ';
					}
					i++;
				}
				continue;
			}
			i++;
		}
		return new String(result);
	}

	protected ArrayList<Integer> build_the_index_of_the_lines(String text)
	{
		ArrayList<Integer> retval=new ArrayList<Integer>();
		retval.add(Integer.valueOf(0));
		for (int i=0;i<text.length();i++)
		{
			if (text.charAt(i)=='\n')
			{
				retval.add(Integer.valueOf(i+1));
			}
		}
		return retval;
	}

	public String return_the_original_text()
	{
		return this.original_text;
	}

	public String return_the_code_only_text()
	{
		return this.code_only_text;
	}

	public int return_how_many_lines()
	{
		return this.position_where_every_line_starts.size();
	}

	/*Line numbers start from 1, the way an editor counts them*/
	public int return_the_line_number_of_the_position(int position)
	{
		if (position<0)
		{
			return 0;
		}
		int retval=1;
		for (int i=0;i<this.position_where_every_line_starts.size();i++)
		{
			if (this.position_where_every_line_starts.get(i).intValue()<=position)
			{
				retval=i+1;
			}
			else
			{
				break;
			}
		}
		return retval;
	}

	public String return_the_line_at_the_position(int position)
	{
		if (position<0 || position>=this.original_text.length())
		{
			return "";
		}
		int start_of_the_line=position;
		while (start_of_the_line>0 && this.original_text.charAt(start_of_the_line-1)!='\n')
		{
			start_of_the_line--;
		}
		int end_of_the_line=position;
		while (end_of_the_line<this.original_text.length() && this.original_text.charAt(end_of_the_line)!='\n')
		{
			end_of_the_line++;
		}
		String retval=this.original_text.substring(start_of_the_line,end_of_the_line).trim();
		if (retval.length()>200)
		{
			retval=retval.substring(0,200)+" ...";
		}
		return retval;
	}

	/*Positions of a piece of text, looking at the code only, so matches inside comments and strings are not reported*/
	public ArrayList<Integer> return_the_positions_in_the_code_of(String needle)
	{
		ArrayList<Integer> retval=new ArrayList<Integer>();
		if (needle==null || needle.equals(""))
		{
			return retval;
		}
		int position=this.code_only_text.indexOf(needle);
		while (position>=0)
		{
			retval.add(Integer.valueOf(position));
			position=this.code_only_text.indexOf(needle,position+1);
		}
		return retval;
	}

	/*Positions of a piece of text anywhere, including inside comments and strings. Used for the markers that must not survive*/
	public ArrayList<Integer> return_the_positions_anywhere_of(String needle)
	{
		ArrayList<Integer> retval=new ArrayList<Integer>();
		if (needle==null || needle.equals(""))
		{
			return retval;
		}
		int position=this.original_text.indexOf(needle);
		while (position>=0)
		{
			retval.add(Integer.valueOf(position));
			position=this.original_text.indexOf(needle,position+1);
		}
		return retval;
	}

	public int return_how_many_times_in_the_code(String needle)
	{
		return return_the_positions_in_the_code_of(needle).size();
	}

	/*
	 * The difference between the opening and the closing character, counted over the code only.
	 * A result other than zero means the generated script cannot possibly parse.
	 */
	public int return_the_balance_of(char opening_char,char closing_char)
	{
		int balance=0;
		for (int i=0;i<this.code_only_text.length();i++)
		{
			char current_char=this.code_only_text.charAt(i);
			if (current_char==opening_char) { balance++; }
			else if (current_char==closing_char) { balance--; }
		}
		return balance;
	}

	/*The position where a closing character appears without a matching opening one, or -1 when that never happens*/
	public int return_the_position_where_the_balance_goes_negative(char opening_char,char closing_char)
	{
		int balance=0;
		for (int i=0;i<this.code_only_text.length();i++)
		{
			char current_char=this.code_only_text.charAt(i);
			if (current_char==opening_char) { balance++; }
			else if (current_char==closing_char)
			{
				balance--;
				if (balance<0)
				{
					return i;
				}
			}
		}
		return -1;
	}

	/*
	 * Given the position of an opening character, returns the position of the one that closes it, or -1.
	 * Used to cut out the whole text of a call, so that a check can look inside one Interceptor.replace() and nowhere else.
	 */
	public int return_the_position_that_closes(int position_of_the_opening_char,char opening_char,char closing_char)
	{
		if (position_of_the_opening_char<0 || position_of_the_opening_char>=this.code_only_text.length())
		{
			return -1;
		}
		int balance=0;
		for (int i=position_of_the_opening_char;i<this.code_only_text.length();i++)
		{
			char current_char=this.code_only_text.charAt(i);
			if (current_char==opening_char) { balance++; }
			else if (current_char==closing_char)
			{
				balance--;
				if (balance==0)
				{
					return i;
				}
			}
		}
		return -1;
	}

	/*
	 * The text of a region that starts at the given position and ends where the first parenthesis that follows it is
	 * closed. The returned text is the ORIGINAL one, comments and strings included, because a check may want to look at
	 * what is printed inside it.
	 */
	public String return_the_text_of_the_call_that_starts_at(int position_of_the_name_of_the_call)
	{
		int position_of_the_open_paren=this.code_only_text.indexOf("(",position_of_the_name_of_the_call);
		if (position_of_the_open_paren<0)
		{
			return "";
		}
		int position_of_the_close_paren=return_the_position_that_closes(position_of_the_open_paren,'(',')');
		if (position_of_the_close_paren<0)
		{
			/*The call is not closed at all, which the balance check reports on its own. Return what is left, so that the caller can still look at it*/
			return this.original_text.substring(position_of_the_name_of_the_call);
		}
		return this.original_text.substring(position_of_the_name_of_the_call,position_of_the_close_paren+1);
	}

	/*
	 * The same region as above, but taken out of the code instead of out of the text: the comments and the strings inside it
	 * have been blanked out.
	 * Careful: this is the one to use when looking for a construct of the language inside a call. A hook that prints its
	 * parameters carries the text args[0] inside a message, and a check that looks for args[] in the text of the call would
	 * find that message and report a hook that is perfectly correct.
	 */
	public String return_the_code_of_the_call_that_starts_at(int position_of_the_name_of_the_call)
	{
		int position_of_the_open_paren=this.code_only_text.indexOf("(",position_of_the_name_of_the_call);
		if (position_of_the_open_paren<0)
		{
			return "";
		}
		int position_of_the_close_paren=return_the_position_that_closes(position_of_the_open_paren,'(',')');
		if (position_of_the_close_paren<0)
		{
			return this.code_only_text.substring(position_of_the_name_of_the_call);
		}
		return this.code_only_text.substring(position_of_the_name_of_the_call,position_of_the_close_paren+1);
	}

	/*
	 * Every name that the script declares: var/let/const, the names of the functions, and the names of the parameters of
	 * every function, including the shorthand methods of an object literal such as the onAdded(module) of the observer.
	 */
	public LinkedHashSet<String> return_all_the_declared_names()
	{
		LinkedHashSet<String> retval=new LinkedHashSet<String>();
		collect_the_names_that_follow_a_keyword(retval,"var");
		collect_the_names_that_follow_a_keyword(retval,"let");
		collect_the_names_that_follow_a_keyword(retval,"const");
		collect_the_names_of_the_functions(retval);
		collect_the_names_of_the_parameters(retval);
		return retval;
	}

	protected void collect_the_names_that_follow_a_keyword(LinkedHashSet<String> set_to_fill,String keyword)
	{
		ArrayList<Integer> positions=return_the_positions_in_the_code_of(keyword);
		for (int i=0;i<positions.size();i++)
		{
			int position=positions.get(i).intValue();
			if (!is_the_position_the_start_of_a_word(position) || !is_the_position_after_the_word_a_separator(position+keyword.length()))
			{
				continue;	//this is not the keyword, it is a piece of a longer name
			}
			int position_after_the_keyword=position+keyword.length();
			/*Only the first name of the declaration is taken. The generated code never declares more than one name at a time, and taking fewer declarations than there are can only make a check milder, never wrong*/
			String name_being_declared=read_the_word_that_starts_after(position_after_the_keyword);
			if (!name_being_declared.equals(""))
			{
				set_to_fill.add(name_being_declared);
			}
		}
	}

	protected void collect_the_names_of_the_functions(LinkedHashSet<String> set_to_fill)
	{
		ArrayList<Integer> positions=return_the_positions_in_the_code_of("function");
		for (int i=0;i<positions.size();i++)
		{
			int position=positions.get(i).intValue();
			if (!is_the_position_the_start_of_a_word(position) || !is_the_position_after_the_word_a_separator(position+8))
			{
				continue;
			}
			String name_of_the_function=read_the_word_that_starts_after(position+8);
			if (!name_of_the_function.equals(""))
			{
				set_to_fill.add(name_of_the_function);
			}
		}
	}

	/*
	 * Reads the parameter list of everything that looks like a callable: <name>(<params>) followed by a {, and also the
	 * (<params>) => form. Only plain names are taken from the list, anything else is ignored.
	 */
	protected void collect_the_names_of_the_parameters(LinkedHashSet<String> set_to_fill)
	{
		for (int i=0;i<this.code_only_text.length();i++)
		{
			if (this.code_only_text.charAt(i)!='(')
			{
				continue;
			}
			int position_of_the_close_paren=return_the_position_that_closes(i,'(',')');
			if (position_of_the_close_paren<0)
			{
				continue;
			}
			/*What follows the parenthesis decides whether this was a parameter list or an ordinary call*/
			int position_after=position_of_the_close_paren+1;
			while (position_after<this.code_only_text.length() && Character.isWhitespace(this.code_only_text.charAt(position_after)))
			{
				position_after++;
			}
			Boolean this_is_a_parameter_list=false;
			if (position_after<this.code_only_text.length() && this.code_only_text.charAt(position_after)=='{')
			{
				this_is_a_parameter_list=true;
			}
			if (position_after+1<this.code_only_text.length() && this.code_only_text.charAt(position_after)=='=' && this.code_only_text.charAt(position_after+1)=='>')
			{
				this_is_a_parameter_list=true;
			}
			if (!this_is_a_parameter_list.booleanValue())
			{
				continue;
			}

			/*
			 * The name that comes right before the parameter list is declared as well. That is what a method of an object
			 * literal looks like, the onAdded(module) of the module observer being the one that the plugin generates, and
			 * without this it would look like a name that the script uses without declaring it. The keywords that are
			 * followed by a parenthesis and a brace, such as if and catch, end up here too, which is harmless.
			 */
			int position_before_the_parameters=i-1;
			while (position_before_the_parameters>=0 && Character.isWhitespace(this.code_only_text.charAt(position_before_the_parameters)))
			{
				position_before_the_parameters--;
			}
			int position_of_the_end_of_the_name=position_before_the_parameters+1;
			while (position_before_the_parameters>=0 && is_a_character_that_can_be_inside_a_name(this.code_only_text.charAt(position_before_the_parameters)).booleanValue())
			{
				position_before_the_parameters--;
			}
			if (position_of_the_end_of_the_name>position_before_the_parameters+1)
			{
				String name_before_the_parameters=this.code_only_text.substring(position_before_the_parameters+1,position_of_the_end_of_the_name);
				if (is_a_plain_javascript_name(name_before_the_parameters).booleanValue())
				{
					set_to_fill.add(name_before_the_parameters);
				}
			}

			String text_of_the_parameters=this.code_only_text.substring(i+1,position_of_the_close_paren);
			String[] parts_of_the_parameters=text_of_the_parameters.split(",");
			for (int j=0;j<parts_of_the_parameters.length;j++)
			{
				String name_of_the_parameter=parts_of_the_parameters[j].trim();
				if (is_a_plain_javascript_name(name_of_the_parameter))
				{
					set_to_fill.add(name_of_the_parameter);
				}
			}
		}
	}

	/*
	 * Every name that the code refers to, excluding the ones that are only a property of something else (the part after a
	 * dot) and excluding the keys of the object literals. This is what makes it possible to notice that the script refers
	 * to something that it never declares, which is how a marker that was never replaced, or a mistyped variable, shows up.
	 */
	public ArrayList<NameThatIsReferred> return_all_the_names_that_are_referred_to()
	{
		ArrayList<NameThatIsReferred> retval=new ArrayList<NameThatIsReferred>();
		int i=0;
		int length_of_text=this.code_only_text.length();
		while (i<length_of_text)
		{
			char current_char=this.code_only_text.charAt(i);
			if (!is_a_character_that_can_start_a_name(current_char))
			{
				i++;
				continue;
			}
			int start_of_the_name=i;
			while (i<length_of_text && is_a_character_that_can_be_inside_a_name(this.code_only_text.charAt(i)))
			{
				i++;
			}
			String name=this.code_only_text.substring(start_of_the_name,i);

			/*
			 * Careful: a hexadecimal number has to be skipped here. The scanner starts a name at the x of 0x1234, because a
			 * digit cannot start a name and an x can, and it would then report x1234 as a name that is never declared. A
			 * name is never written immediately after a digit in javascript, so a digit right before it means this is the
			 * tail of a number and not a name at all.
			 */
			if (start_of_the_name>0 && Character.isDigit(this.code_only_text.charAt(start_of_the_name-1)))
			{
				continue;
			}

			/*Skip the part after a dot, it is the name of a property and not of a variable*/
			int position_before=start_of_the_name-1;
			while (position_before>=0 && Character.isWhitespace(this.code_only_text.charAt(position_before)))
			{
				position_before--;
			}
			if (position_before>=0 && this.code_only_text.charAt(position_before)=='.')
			{
				continue;
			}

			/*Skip the keys of an object literal, which are followed by a colon*/
			int position_after=i;
			while (position_after<length_of_text && Character.isWhitespace(this.code_only_text.charAt(position_after)))
			{
				position_after++;
			}
			if (position_after<length_of_text && this.code_only_text.charAt(position_after)==':')
			{
				continue;
			}

			retval.add(new NameThatIsReferred(name,start_of_the_name));
		}
		return retval;
	}

	protected Boolean is_the_position_the_start_of_a_word(int position)
	{
		if (position<=0)
		{
			return true;
		}
		return Boolean.valueOf(!is_a_character_that_can_be_inside_a_name(this.code_only_text.charAt(position-1)));
	}

	protected Boolean is_the_position_after_the_word_a_separator(int position)
	{
		if (position>=this.code_only_text.length())
		{
			return true;
		}
		return Boolean.valueOf(!is_a_character_that_can_be_inside_a_name(this.code_only_text.charAt(position)));
	}

	protected String read_the_word_that_starts_after(int position)
	{
		int i=position;
		while (i<this.code_only_text.length() && Character.isWhitespace(this.code_only_text.charAt(i)))
		{
			i++;
		}
		int start_of_the_word=i;
		while (i<this.code_only_text.length() && is_a_character_that_can_be_inside_a_name(this.code_only_text.charAt(i)))
		{
			i++;
		}
		if (i==start_of_the_word)
		{
			return "";
		}
		return this.code_only_text.substring(start_of_the_word,i);
	}

	public static Boolean is_a_character_that_can_start_a_name(char c)
	{
		return Boolean.valueOf(Character.isLetter(c) || c=='_' || c=='$');
	}

	public static Boolean is_a_character_that_can_be_inside_a_name(char c)
	{
		return Boolean.valueOf(Character.isLetterOrDigit(c) || c=='_' || c=='$');
	}

	/*Whether a piece of text is a name that javascript would accept as an identifier*/
	public static Boolean is_a_plain_javascript_name(String text)
	{
		if (text==null || text.equals(""))
		{
			return false;
		}
		if (!is_a_character_that_can_start_a_name(text.charAt(0)).booleanValue())
		{
			return false;
		}
		for (int i=1;i<text.length();i++)
		{
			if (!is_a_character_that_can_be_inside_a_name(text.charAt(i)).booleanValue())
			{
				return false;
			}
		}
		return true;
	}

	/*A name that the code refers to, together with where it was found*/
	public class NameThatIsReferred
	{
		public String name;
		public int position;

		public NameThatIsReferred(String name,int position)
		{
			this.name=name;
			this.position=position;
		}
	}
}
