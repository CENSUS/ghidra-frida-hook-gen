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
		/*Careful: the pattern has to be stripped as well. Without it, a leading or trailing space (which is very easy to bring along when the pattern is pasted) makes the split on the spaces produce an empty part, and the whole pattern is then rejected as invalid*/
		this.incoming_instruction_pattern=incoming_instruction_pattern.toLowerCase().replace("\n"," ").replace("\r"," ").replace("\t"," ").replaceAll(" +", " ").strip();
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
		String modname=this.incoming_module_name_sanitized;
		String retval="";

		retval+=this.spaces+"var pattern_to_search_for_"+modname+"= '"+frida_pattern+"'\n";
		retval+=this.spaces+"\n";

		/*
		 * The name of a module is not spelled the same way everywhere, but the way it varies depends on the platform.
		 * Careful: the tolerance that Windows needs (the case does not matter and the .dll suffix is not always part of the
		 * name) must not be applied everywhere. On the other systems the file names are case sensitive, so being tolerant
		 * there would let libFoo.so match libfoo.so, which is a different library, and its memory would be scanned instead.
		 * The decision is taken at runtime, from Process.platform, because what matters is where the script is running.
		 */
		retval+=this.spaces+"/*The name of a module is not spelled the same way everywhere, and the module may also be known by its full path*/\n";
		retval+=this.spaces+"function does_module_match_the_wanted_name_"+modname+"(module_to_check)\n";
		retval+=this.spaces+"{\n";
		retval+=this.spaces+"    var names_to_compare=[module_to_check.name]\n";
		retval+=this.spaces+"    //the module may be known by its path, so the file name of that path is compared as well\n";
		retval+=this.spaces+"    if (module_to_check.path!==null && module_to_check.path!==undefined)\n";
		retval+=this.spaces+"    {\n";
		retval+=this.spaces+"        var array_of_subdirs=module_to_check.path.split('/')\n";
		retval+=this.spaces+"        var filename_of_module=array_of_subdirs[array_of_subdirs.length-1]\n";
		retval+=this.spaces+"        array_of_subdirs=filename_of_module.split('\\\\')\n";
		retval+=this.spaces+"        names_to_compare.push(array_of_subdirs[array_of_subdirs.length-1])\n";
		retval+=this.spaces+"    }\n";
		retval+=this.spaces+"    for (var nind=0;nind<names_to_compare.length;nind++)\n";
		retval+=this.spaces+"    {\n";
		retval+=this.spaces+"        var name_of_module=names_to_compare[nind]\n";
		retval+=this.spaces+"        if (name_of_module===null || name_of_module===undefined) { continue }\n";
		/*Careful: the tolerance of Windows is written inside the branch that checks the platform, and not behind a variable that was set earlier. It is the same shape as the comparison that the prologues emit, and it keeps everything that mentions a .dll in one place that is plainly guarded*/
		retval+=this.spaces+"        if (Process.platform==='windows')\n";
		retval+=this.spaces+"        {\n";
		retval+=this.spaces+"            //in Windows the case does not matter and the .dll suffix is not always part of the name\n";
		retval+=this.spaces+"            var lowercase_name=name_of_module.toLowerCase()\n";
		retval+=this.spaces+"            var lowercase_wanted_name=module_name_"+modname+".toLowerCase()\n";
		retval+=this.spaces+"            if (lowercase_name===lowercase_wanted_name || lowercase_name+'.dll'===lowercase_wanted_name || lowercase_name===lowercase_wanted_name+'.dll') { return true }\n";
		retval+=this.spaces+"            continue\n";
		retval+=this.spaces+"        }\n";
		retval+=this.spaces+"        //everywhere else the file names are case sensitive, and a library is not a .dll\n";
		retval+=this.spaces+"        if (name_of_module===module_name_"+modname+") { return true }\n";
		retval+=this.spaces+"    }\n";
		retval+=this.spaces+"    return false\n";
		retval+=this.spaces+"}\n";
		retval+=this.spaces+"\n";

		/*Gather the ranges first, so that the scanning itself is one single loop*/
		retval+=this.spaces+"var ranges_to_scan_"+modname+"=[]\n";
		retval+=this.spaces+"var we_found_the_module_"+modname+"=false\n";
		retval+=this.spaces+"var modulemap_for_the_memory_scan_"+modname+"=new ModuleMap()\n";
		retval+=this.spaces+"var all_modules_"+modname+"=Process.enumerateModules()\n";
		retval+=this.spaces+"for (var ind=0;ind<all_modules_"+modname+".length;ind++) {\n";
		retval+=this.spaces+"    if (!does_module_match_the_wanted_name_"+modname+"(all_modules_"+modname+"[ind])) { continue }\n";
		retval+=this.spaces+"    we_found_the_module_"+modname+"=true\n";
		retval+=this.spaces+"    var readable_ranges_of_the_module=all_modules_"+modname+"[ind].enumerateRanges('r--')\n";
		retval+=this.spaces+"    for (var rind=0;rind<readable_ranges_of_the_module.length;rind++) {\n";
		retval+=this.spaces+"        ranges_to_scan_"+modname+".push({range_to_scan:readable_ranges_of_the_module[rind], description_of_range:'module '+all_modules_"+modname+"[ind].name})\n";
		retval+=this.spaces+"    }\n";
		retval+=this.spaces+"}\n";
		retval+=this.spaces+"\n";

		/*Code does not only live inside modules*/
		retval+=this.spaces+"/*Code does not only live inside modules: it can be JIT compiled, unpacked, decrypted or simply copied into an anonymous mapping, and none of that belongs to a module. Those ranges are scanned as well*/\n";
		retval+=this.spaces+"/*Only the executable ones are taken, because what is being looked for is a pattern of instructions. Replace the 'r-x' with 'r--' to scan every readable range that belongs to no module, which finds code that is not executable yet but is a lot slower*/\n";
		retval+=this.spaces+"var ranges_outside_of_the_modules_"+modname+"=Process.enumerateRanges('r-x')\n";
		retval+=this.spaces+"for (var rind=0;rind<ranges_outside_of_the_modules_"+modname+".length;rind++) {\n";
		retval+=this.spaces+"    if (modulemap_for_the_memory_scan_"+modname+".find(ranges_outside_of_the_modules_"+modname+"[rind].base)===null) {\n";
		retval+=this.spaces+"        ranges_to_scan_"+modname+".push({range_to_scan:ranges_outside_of_the_modules_"+modname+"[rind], description_of_range:'memory that belongs to no module'})\n";
		retval+=this.spaces+"    }\n";
		retval+=this.spaces+"}\n";
		retval+=this.spaces+"\n";

		/*And now the scan itself*/
		retval+=this.spaces+"var cnt_of_results_"+modname+"=0\n";
		retval+=this.spaces+"for (var rind=0;rind<ranges_to_scan_"+modname+".length;rind++) {\n";
		retval+=this.spaces+"    var r=ranges_to_scan_"+modname+"[rind].range_to_scan\n";
		retval+=this.spaces+"    var res_of_memscan=[]\n";
		retval+=this.spaces+"    try {\n";
		retval+=this.spaces+"        res_of_memscan=Memory.scanSync(r.base,r.size,pattern_to_search_for_"+modname+")\n";
		retval+=this.spaces+"    } catch (err) {\n";
		retval+=this.spaces+"        //a range can stop being readable between the moment it is enumerated and the moment it is scanned, and one such range must not abort the whole scan\n";
		retval+=this.spaces+"        console.log('Memory scan: the range at '+r.base+' of size '+r.size+' ('+ranges_to_scan_"+modname+"[rind].description_of_range+') could not be scanned, continuing')\n";
		retval+=this.spaces+"        continue\n";
		retval+=this.spaces+"    }\n";
		retval+=this.spaces+"    cnt_of_results_"+modname+"+=res_of_memscan.length\n";
		retval+=this.spaces+"    for (var j=0;j<res_of_memscan.length;j++) {\n";
		retval+=this.spaces+"        var module_of_the_result=modulemap_for_the_memory_scan_"+modname+".find(res_of_memscan[j].address)\n";
		retval+=this.spaces+"        var str_with_the_position_of_the_result=' inside '+ranges_to_scan_"+modname+"[rind].description_of_range\n";
		retval+=this.spaces+"        if (module_of_the_result!==null) { str_with_the_position_of_the_result=' inside module '+JSON.stringify(module_of_the_result)+' with offset '+res_of_memscan[j].address.sub(module_of_the_result.base) }\n";
		retval+=this.spaces+"        console.log('Hooking address '+res_of_memscan[j].address+str_with_the_position_of_the_result)\n";
		retval+=this.spaces+"        //Careful: this has to be declared with let and not with var. A var is scoped to the whole function, so every hook of the loop would close over the same variable and they would all print the message of the last match\n";
		retval+=this.spaces+"        let constructed_str_to_print='Reached address '+res_of_memscan[j].address+str_with_the_position_of_the_result+' due to pattern '+ pattern_to_search_for_"+modname+"\n";
		retval+=this.spaces+"        try {\n";
		retval+=this.spaces+"            Interceptor.attach(res_of_memscan[j].address, () => {\n";
		retval+=this.spaces+"                console.log(constructed_str_to_print)\n";
		retval+=this.spaces+"            })\n";
		retval+=this.spaces+"        } catch (err) { console.log('Could not hook the address '+res_of_memscan[j].address+', continuing') }\n";
		retval+=this.spaces+"    }\n";
		retval+=this.spaces+"}\n";
		retval+=this.spaces+"\n";

		/*The reporting is outside of every loop, so that something is printed even when no module matched the name*/
		retval+=this.spaces+"/*The reporting is done here, outside of the loops, so that something is always printed. It used to be inside the branch that matched the module, which meant that a name that matched nothing produced no output at all*/\n";
		retval+=this.spaces+"if (!we_found_the_module_"+modname+") {\n";
		retval+=this.spaces+"    console.log('Memory scan: no loaded module matched the name '+module_name_"+modname+"+', only the memory that belongs to no module was scanned')\n";
		retval+=this.spaces+"}\n";
		retval+=this.spaces+"if (cnt_of_results_"+modname+"==0) {\n";
		retval+=this.spaces+"    console.log('Memory scan for pattern '+pattern_to_search_for_"+modname+"+' did not give any results in the '+ranges_to_scan_"+modname+".length+' ranges that were scanned')\n";
		retval+=this.spaces+"} else {\n";
		retval+=this.spaces+"    console.log('Memory scan for pattern '+pattern_to_search_for_"+modname+"+' gave '+cnt_of_results_"+modname+"+' results in total, in the '+ranges_to_scan_"+modname+".length+' ranges that were scanned')\n";
		retval+=this.spaces+"}\n";

		return retval;
	}
	
	
}
