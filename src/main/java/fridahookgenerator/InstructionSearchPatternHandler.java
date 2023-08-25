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

import java.util.HashMap;

import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class InstructionSearchPatternHandler {
	
	private PluginTool incoming_plugintool;
	private Program current_program;
	private String incoming_instruction_pattern;
	private String incoming_module_name_sanitized;
	private String spaces;

	public InstructionSearchPatternHandler(PluginTool incoming_plugintool, Program current_program, String incoming_instruction_pattern , String incoming_module_name_sanitized, String spaces ) {
		this.incoming_plugintool=incoming_plugintool;
		this.current_program=current_program;
		this.incoming_instruction_pattern=incoming_instruction_pattern.toLowerCase().replace("\n"," ").replaceAll(" +", " ");
		this.incoming_module_name_sanitized=incoming_module_name_sanitized;
		this.spaces=spaces;
	}
	
	protected Boolean is_valid_incoming_instruction_pattern(String incoming_instruction_pattern)
	{
		String allowed_characters="0123456789abcdef[]. ";
		
		for (int i=0;i<incoming_instruction_pattern.length();i++)
		{
			char tmpchar=incoming_instruction_pattern.charAt(i);
			if (allowed_characters.indexOf(tmpchar)<0)
			{
				return false;
			}
		}
		return true;
	}

	protected Boolean is_valid_pattern_for_byte(String pattern_for_byte)
	{
		String hex_chars="0123456789abcdef";
		if (pattern_for_byte.length()==2)
		{
			if (hex_chars.indexOf(pattern_for_byte.charAt(0))>=0 && hex_chars.indexOf(pattern_for_byte.charAt(1))>=0)
			{
				return true;
			}
		}
		if (pattern_for_byte.length()==10)
		{
			if (pattern_for_byte.charAt(0)=='[' && pattern_for_byte.charAt(9)==']')
			{
				for (int i=1;i<=8;i++)
				{
					if (pattern_for_byte.charAt(i)!='0' && pattern_for_byte.charAt(i)!='1' && pattern_for_byte.charAt(i)!='.')
					{
						return false;
					}
				}
				return true;
			}
		}
		
		return false;
	}
	
	protected String return_frida_pattern_for_incoming_instruction_pattern(String incoming_instruction_pattern)
	{
		/*
		 * 5b 
		 * 5d 
         * [01001...] 8d 15 25 da 34 00 
		 */
		
		String res_pattern="";
		String mask_pattern="";
		
		if (!is_valid_incoming_instruction_pattern(incoming_instruction_pattern))
		{
			return "ERROR";
		}
		String[] parts_of_pattern=incoming_instruction_pattern.split(" ");
		for (int i=0;i<parts_of_pattern.length;i++)
		{
			String tmpbytepattern=parts_of_pattern[i];
			if (!is_valid_pattern_for_byte(tmpbytepattern))
			{
				return "ERROR";
			}
			if (tmpbytepattern.length()==2)
			{
				res_pattern+=tmpbytepattern+" ";
				mask_pattern+="ff ";
			}
			if (tmpbytepattern.length()==10)
			{
				String tmpres_for_byte="";
				String tmpmask_for_byte="";
				
				for (int j=1;j<=8;j++)
				{
					if (tmpbytepattern.charAt(j)=='.')
					{
						tmpres_for_byte+="0";
						tmpmask_for_byte+="0";
					}
					else
					{
						tmpres_for_byte+=tmpbytepattern.charAt(j);
						tmpmask_for_byte+="1";
					}
				}
				
				String byte_to_add_to_res=Integer.toString(Integer.parseInt(tmpres_for_byte,2),16);
				String byte_to_add_to_mask=Integer.toString(Integer.parseInt(tmpmask_for_byte,2),16);
				if (byte_to_add_to_res.length()==1)
				{
					byte_to_add_to_res="0"+byte_to_add_to_res;
				}
				if (byte_to_add_to_mask.length()==1)
				{
					byte_to_add_to_mask="0"+byte_to_add_to_mask;
				}
								
				res_pattern+=byte_to_add_to_res+" ";
				mask_pattern+=byte_to_add_to_mask+" ";
			}
		}
		return (res_pattern+": "+mask_pattern).trim();
	}
	
	
	protected String return_frida_code_for_incoming_instruction_pattern()
	{
		String frida_pattern=this.return_frida_pattern_for_incoming_instruction_pattern(this.incoming_instruction_pattern);
		if (frida_pattern.equals("ERROR"))
		{
			return "//Given pattern for Memory Scan is not valid\n";
		}
		String retval="";
		retval+=this.spaces+"var pattern_to_search_for= '"+frida_pattern+"'\n";
		retval+=this.spaces+"var loaded_modules= Process.enumerateModulesSync()\n";
		retval+=this.spaces+"for (var ind=0;ind<loaded_modules.length;ind++) {\n";
		retval+=this.spaces+"    if (loaded_modules[ind].name===module_name_"+this.incoming_module_name_sanitized+") //Comment out if you want to search in every loaded module\n";
		retval+=this.spaces+"    //if (loaded_modules[ind].name.toLowerCase().search('frida')===-1) //Comment out if you want to search in every loaded module\n";
		retval+=this.spaces+"    {\n";
		retval+=this.spaces+"        var m=loaded_modules[ind]\n";
		retval+=this.spaces+"        var ranges=m.enumerateRanges('r--')\n";
		retval+=this.spaces+"        var cnt_of_results_for_module=0\n";
		retval+=this.spaces+"        for (var rind=0;rind<ranges.length;rind++) {\n";
		retval+=this.spaces+"            var r=ranges[rind]\n";
		retval+=this.spaces+"            var res_of_memscan=Memory.scanSync(r.base,r.size,pattern_to_search_for)\n";
		retval+=this.spaces+"            if (res_of_memscan.length>0) {\n";
		retval+=this.spaces+"                //console.log('Found '+res_of_memscan.length+' results for pattern '+pattern_to_search_for+' inside module '+JSON.stringify(m)+' and range '+JSON.stringify(r))\n";
		retval+=this.spaces+"                cnt_of_results_for_module+=res_of_memscan.length\n";
		retval+=this.spaces+"                for (var j=0;j<res_of_memscan.length;j++) {\n";
		retval+=this.spaces+"                    console.log('Hooking address '+res_of_memscan[j].address+' from module '+JSON.stringify(m)+ ' with offset '+res_of_memscan[j].address.sub(m.base))\n";
		retval+=this.spaces+"                    var constructed_str_to_print='Reached address '+res_of_memscan[j].address+' inside module '+JSON.stringify(m)+ ' with offset '+res_of_memscan[j].address.sub(m.base)+' due to pattern '+ pattern_to_search_for \n";
		retval+=this.spaces+"                    Interceptor.attach(res_of_memscan[j].address, () => {\n";
		retval+=this.spaces+"                        console.log(constructed_str_to_print)\n";
		retval+=this.spaces+"				     })\n";
		retval+=this.spaces+"                }\n";
		retval+=this.spaces+"            }\n";
		retval+=this.spaces+"        }\n";
		retval+=this.spaces+"        if (cnt_of_results_for_module==0) {\n";
		retval+=this.spaces+"            console.log('Memory scan for pattern '+pattern_to_search_for+' did not give any results inside module '+JSON.stringify(m))\n";
		retval+=this.spaces+"        } else {\n";
		retval+=this.spaces+"            console.log('Memory scan for pattern '+pattern_to_search_for+' gave '+cnt_of_results_for_module+' results in total inside module '+JSON.stringify(m))\n";
		retval+=this.spaces+"        }\n";
		retval+=this.spaces+"    }\n";
		retval+=this.spaces+"}\n";
		
		return retval;
	}
	
	
}
