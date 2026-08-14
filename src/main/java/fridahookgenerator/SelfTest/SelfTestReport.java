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
import java.util.LinkedHashMap;

/*
 * Collects the findings of the self test and prints them in a way that stays readable.
 *
 * The rule that keeps the output from becoming noise: findings are grouped by their signature, and a group is printed as
 * one line with the number of times it happened, followed by at most a few examples. A generated script with thirty
 * thousand hooks that has one systematic problem therefore produces four lines, not thirty thousand.
 */
public class SelfTestReport {

	protected LinkedHashMap<String,ArrayList<SelfTestFinding>> findings_grouped_by_signature;
	protected ArrayList<String> lines_of_the_summary_of_every_step;
	protected int how_many_examples_to_print_per_group=3;
	protected int how_many_checks_were_run;
	protected int how_many_steps_were_skipped;
	protected String name_of_the_current_combination;

	public SelfTestReport()
	{
		this.findings_grouped_by_signature=new LinkedHashMap<String,ArrayList<SelfTestFinding>>();
		this.lines_of_the_summary_of_every_step=new ArrayList<String>();
		this.how_many_checks_were_run=0;
		this.how_many_steps_were_skipped=0;
		this.name_of_the_current_combination="";
	}

	/*Everything that is reported from now on is attributed to this combination of options*/
	public void set_the_current_combination(String name_of_combination)
	{
		this.name_of_the_current_combination=name_of_combination;
	}

	public void count_one_check_that_was_run()
	{
		this.how_many_checks_were_run++;
	}

	public SelfTestFinding add_finding(SelfTestFinding finding)
	{
		finding.name_of_combination=this.name_of_the_current_combination;
		String signature=finding.return_signature();
		if (!this.findings_grouped_by_signature.containsKey(signature))
		{
			this.findings_grouped_by_signature.put(signature,new ArrayList<SelfTestFinding>());
		}
		this.findings_grouped_by_signature.get(signature).add(finding);
		return finding;
	}

	public SelfTestFinding add_error(String name_of_check,String signature,String summary,String detail,int line_number_in_script)
	{
		return add_finding(new SelfTestFinding(SelfTestFinding.Severity.ERROR,name_of_check,signature,summary,detail,line_number_in_script));
	}

	public SelfTestFinding add_warning(String name_of_check,String signature,String summary,String detail,int line_number_in_script)
	{
		return add_finding(new SelfTestFinding(SelfTestFinding.Severity.WARNING,name_of_check,signature,summary,detail,line_number_in_script));
	}

	/*
	 * Careful: the summary of a note takes part in its signature. A note usually carries a number, and that number is
	 * different for every combination, so grouping the notes by the signature alone would print the number of the first one
	 * and hide all the others, which is worse than not printing them at all.
	 */
	public SelfTestFinding add_info(String name_of_check,String signature,String summary,String detail)
	{
		return add_finding(new SelfTestFinding(SelfTestFinding.Severity.INFO,name_of_check,signature+"|"+summary,summary,detail,0));
	}

	/*A step that could not be run at all, for example a check for an architecture that the loaded program is not*/
	public void add_skipped_step(String name_of_step,String why)
	{
		this.how_many_steps_were_skipped++;
		this.lines_of_the_summary_of_every_step.add("  SKIP  "+name_of_step+"  ("+why+")");
	}

	/*Called after every combination, so that the reader sees one line per combination even when everything passed*/
	public void add_summary_of_a_step(String name_of_step,int how_many_errors,int how_many_warnings,String extra_information)
	{
		String verdict="  ok  ";
		if (how_many_errors>0)
		{
			verdict="  FAIL";
		}
		else if (how_many_warnings>0)
		{
			verdict="  warn";
		}
		String line=verdict+"  "+name_of_step;
		if (how_many_errors>0 || how_many_warnings>0)
		{
			line+="   ("+how_many_errors+" errors, "+how_many_warnings+" warnings)";
		}
		if (extra_information!=null && !extra_information.equals(""))
		{
			line+="   "+extra_information;
		}
		this.lines_of_the_summary_of_every_step.add(line);
	}

	public int return_how_many_of_severity(SelfTestFinding.Severity severity)
	{
		int retval=0;
		for (String signature: this.findings_grouped_by_signature.keySet())
		{
			ArrayList<SelfTestFinding> findings_of_this_signature=this.findings_grouped_by_signature.get(signature);
			for (int i=0;i<findings_of_this_signature.size();i++)
			{
				if (findings_of_this_signature.get(i).return_severity()==severity)
				{
					retval++;
				}
			}
		}
		return retval;
	}

	public Boolean did_the_self_test_pass()
	{
		return Boolean.valueOf(return_how_many_of_severity(SelfTestFinding.Severity.ERROR)==0);
	}

	/*Builds the whole report. The errors come first, because they are the reason somebody ran this*/
	public String return_the_whole_report()
	{
		StringBuffer sb=new StringBuffer(65536);

		sb.append("\n");
		sb.append("=======================================================================\n");
		sb.append(" FridaHookGenerator self test\n");
		sb.append("=======================================================================\n");

		int how_many_errors=return_how_many_of_severity(SelfTestFinding.Severity.ERROR);
		int how_many_warnings=return_how_many_of_severity(SelfTestFinding.Severity.WARNING);

		append_the_groups_of_severity(sb,SelfTestFinding.Severity.ERROR,"ERRORS");
		append_the_groups_of_severity(sb,SelfTestFinding.Severity.WARNING,"WARNINGS");
		append_the_groups_of_severity(sb,SelfTestFinding.Severity.INFO,"NOTES");

		sb.append("\n");
		sb.append("-- what was run ------------------------------------------------------\n");
		for (int i=0;i<this.lines_of_the_summary_of_every_step.size();i++)
		{
			sb.append(this.lines_of_the_summary_of_every_step.get(i));
			sb.append("\n");
		}

		sb.append("\n");
		sb.append("-- verdict -----------------------------------------------------------\n");
		sb.append(" checks run: "+this.how_many_checks_were_run+" , steps skipped: "+this.how_many_steps_were_skipped+"\n");
		sb.append(" errors: "+how_many_errors+" , warnings: "+how_many_warnings+"\n");
		if (how_many_errors==0)
		{
			sb.append(" RESULT: PASS\n");
		}
		else
		{
			sb.append(" RESULT: FAIL\n");
		}
		sb.append("=======================================================================\n");

		return sb.toString();
	}

	protected void append_the_groups_of_severity(StringBuffer sb,SelfTestFinding.Severity severity,String title_of_the_section)
	{
		/*First find out whether there is anything of this severity at all, so that an empty section is not printed*/
		Boolean there_is_something_to_print=false;
		for (String signature: this.findings_grouped_by_signature.keySet())
		{
			if (this.findings_grouped_by_signature.get(signature).get(0).return_severity()==severity)
			{
				there_is_something_to_print=true;
			}
		}
		if (!there_is_something_to_print.booleanValue())
		{
			return;
		}

		sb.append("\n");
		sb.append("-- "+title_of_the_section+" ------------------------------------------------------\n");

		int number_of_the_group=0;
		for (String signature: this.findings_grouped_by_signature.keySet())
		{
			ArrayList<SelfTestFinding> findings_of_this_signature=this.findings_grouped_by_signature.get(signature);
			SelfTestFinding first_finding=findings_of_this_signature.get(0);
			if (first_finding.return_severity()!=severity)
			{
				continue;
			}
			number_of_the_group++;
			sb.append("\n");
			sb.append(" ["+number_of_the_group+"] "+first_finding.return_name_of_check()+": "+first_finding.return_summary());
			if (findings_of_this_signature.size()>1)
			{
				sb.append("   (happened "+findings_of_this_signature.size()+" times)");
			}
			sb.append("\n");
			/*
			 * A note carries no evidence worth laying out, only its own sentence, so it is printed on one line. An error or a
			 * warning gets the whole layout: what was asked, what was expected, what was found, where, and the piece of the
			 * generated script that it is about.
			 */
			if (severity==SelfTestFinding.Severity.INFO)
			{
				for (int i=0;i<findings_of_this_signature.size() && i<this.how_many_examples_to_print_per_group;i++)
				{
					String the_detail=findings_of_this_signature.get(i).what_was_found;
					if (!the_detail.equals(""))
					{
						sb.append("       "+the_detail+"\n");
					}
				}
				continue;
			}

			int how_many_examples_printed=0;
			for (int i=0;i<findings_of_this_signature.size() && how_many_examples_printed<this.how_many_examples_to_print_per_group;i++)
			{
				if (how_many_examples_printed>0)
				{
					sb.append("\n");
				}
				sb.append(findings_of_this_signature.get(i).return_the_evidence("       "));
				how_many_examples_printed++;
			}
			if (findings_of_this_signature.size()>how_many_examples_printed)
			{
				sb.append("       ... and "+(findings_of_this_signature.size()-how_many_examples_printed)+" more of the same\n");
			}
		}
	}
}
