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

/*
 * One thing that the self test found.
 *
 * A finding has to answer four questions for somebody who is reading the report and did not write the check: what was
 * being asked (the condition), what the answer should have been, what the answer actually was, and where. Those are kept
 * in fields of their own instead of being written into one sentence, so that the report can lay them out in a way that can
 * be read at a glance.
 *
 * Careful: the signature is what makes two findings "the same kind of problem", and it must never carry anything that
 * belongs to one single instance, such as the name of a hook or an address. If it does, then a problem that happens on a
 * thousand hooks is reported as a thousand different problems, which is exactly the kind of output that nobody reads.
 */
public class SelfTestFinding {

	public enum Severity {
		ERROR,		//something is definitely wrong: the generated script is broken or contradicts the database
		WARNING,	//something looks wrong, or an assumption of the plugin does not hold, but it may be acceptable
		INFO		//worth knowing, never a failure
	};

	protected Severity severity;
	protected String name_of_check;			//which check produced this
	protected String signature;			//findings with the same signature are collapsed together
	protected String summary;			//one line, what is wrong

	/*The four questions. Any of them may be left empty, and then it is simply not printed*/
	public String condition="";			//the thing that was asked, written the way the check asks it
	public String what_was_expected="";
	public String what_was_found="";
	public String where="";				//the hook, the address, the option: whatever locates this instance

	/*The piece of the generated script that the finding is about, printed with its line numbers under the finding*/
	public String context_text="";
	public String name_of_the_context="";		//for example "the hook, as it was generated"

	protected String name_of_combination="";	//which combination of options was being generated
	protected int line_number_in_script;		//0 when it does not apply

	public SelfTestFinding(Severity severity,String name_of_check,String signature,String summary,String detail,int line_number_in_script)
	{
		this.severity=severity;
		this.name_of_check=name_of_check;
		this.signature=signature;
		this.summary=summary;
		this.what_was_found=detail;		//the old, single line form of a finding lands here
		this.line_number_in_script=line_number_in_script;
	}

	public Severity return_severity()
	{
		return this.severity;
	}

	public String return_signature()
	{
		return this.name_of_check+"|"+this.signature;
	}

	public String return_name_of_check()
	{
		return this.name_of_check;
	}

	public String return_summary()
	{
		return this.summary;
	}

	/*Fills in the three fields that describe what was asked and what happened, and returns itself so that a check can do it in one line*/
	public SelfTestFinding with(String condition,String what_was_expected,String what_was_found)
	{
		this.condition=condition;
		this.what_was_expected=what_was_expected;
		this.what_was_found=what_was_found;
		return this;
	}

	public SelfTestFinding at(String where)
	{
		this.where=where;
		return this;
	}

	public SelfTestFinding with_the_context(String name_of_the_context,String context_text)
	{
		this.name_of_the_context=name_of_the_context;
		this.context_text=context_text;
		return this;
	}

	/*
	 * How one instance of a finding is printed under its group. Everything that was filled in gets its own labelled line,
	 * and the piece of the generated script, when there is one, is printed after them with its line numbers.
	 */
	public String return_the_evidence(String indentation)
	{
		StringBuffer sb=new StringBuffer(512);

		String the_place=this.where;
		if (this.line_number_in_script>0)
		{
			if (!the_place.equals(""))
			{
				the_place+=" , ";
			}
			the_place+="line "+this.line_number_in_script+" of the script";
		}
		if (!this.name_of_combination.equals(""))
		{
			if (!the_place.equals(""))
			{
				the_place+=" , ";
			}
			the_place+="combination \""+this.name_of_combination+"\"";
		}

		if (!the_place.equals(""))
		{
			sb.append(indentation+"where     : "+the_place+"\n");
		}
		if (!this.condition.equals(""))
		{
			sb.append(indentation+"condition : "+this.condition+"\n");
		}
		if (!this.what_was_expected.equals(""))
		{
			sb.append(indentation+"expected  : "+this.what_was_expected+"\n");
		}
		if (!this.what_was_found.equals(""))
		{
			sb.append(indentation+"found     : "+this.what_was_found+"\n");
		}
		if (!this.context_text.equals(""))
		{
			sb.append(indentation+"--- "+(this.name_of_the_context.equals("")?"the generated code":this.name_of_the_context)+" ---\n");
			String[] lines=this.context_text.split("\n",-1);
			int how_many_lines_at_most=40;
			for (int i=0;i<lines.length && i<how_many_lines_at_most;i++)
			{
				sb.append(indentation+"  "+lines[i]+"\n");
			}
			if (lines.length>how_many_lines_at_most)
			{
				sb.append(indentation+"  ... and "+(lines.length-how_many_lines_at_most)+" more lines\n");
			}
		}
		return sb.toString();
	}
}
