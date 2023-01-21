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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

/*
 * Sister class of HookGenerator, containing many useful functions that are called sometime in its code. It receives a reference to it and uses its internal variables.
 */
 
public class HookGeneratorUtils {

	private HookGenerator incoming_hook_generator;
	private String characters_allowed_in_variable_name="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";

	
	public HookGeneratorUtils(HookGenerator incoming_hook_generator)
	{
		this.incoming_hook_generator = incoming_hook_generator;
	}
	

	protected String generate_epilogue_for_address(Address addr, Boolean print_debug) {
		
		String hook_str="";
		
		if (!this.incoming_hook_generator.isAdvanced || (this.incoming_hook_generator.isAdvanced && !this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked) || (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.incoming_hook_generator.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==0))
		{
			//default method
			hook_str+="      \n";
			hook_str+="      Interceptor.flush();\n"
					+ "      console.log(\"Registered interceptors.\");\n"
					+ "    }, 2000);//milliseconds\n"
					+ "}\n"
					+ "start_timer_for_intercept();\n";
		}
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.incoming_hook_generator.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==1 ||
				this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.incoming_hook_generator.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==2 )
		{
			//dlopen() or LoadLibrary() method
			hook_str+="      \n"
					+ "      Interceptor.flush();\n"
					+ "      console.log(\"Registered interceptors.\");\n"
					+ "}\n";
		}
		
		return hook_str;
				
	}
	
	
	protected String generate_prologue_for_address(Address addr, Boolean print_debug) {
		
		String hook_str="";
		
		if (!this.incoming_hook_generator.isAdvanced || (this.incoming_hook_generator.isAdvanced && !this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked) || (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.incoming_hook_generator.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==0))
		{
			//default method
			hook_str+="var module_name_"+this.incoming_hook_generator.current_program_name_sanitized+"='"+this.incoming_hook_generator.current_program_name+"';\n";
			hook_str+="\n";
			hook_str+="function start_timer_for_intercept() {\n"
					+ "  setTimeout(\n"
					+ "    function() {\n"
					+ "      console.log(\"Registering interceptors...\");\n";
			hook_str+="      \n";
			hook_str+="      \n";
		}
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.incoming_hook_generator.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==1)
		{
			//dlopen() method
			hook_str+="var module_name_"+this.incoming_hook_generator.current_program_name_sanitized+"='"+this.incoming_hook_generator.current_program_name+"';\n";
			hook_str+="\n";
			hook_str+="function extract_libname_from_dlopen_arg(dlopen_arg)\n"
					+ "{\n"
					+ "    if (dlopen_arg!==null && dlopen_arg.indexOf(\"/\")>=0)\n"
					+ "    {\n"
					+ "        var array_of_subdirs=dlopen_arg.split(\"/\");\n"
					+ "        return array_of_subdirs[array_of_subdirs.length-1];\n"
					+ "    }\n"
					+ "    else\n"
					+ "    {\n"
					+ "        return dlopen_arg;\n"
					+ "    }\n"
					+ "}\n"
					+ "\n"
					+ "function do_the_dlopen_interception(incoming_export)\n"
					+ "{\n"
					+ "    try "
					+ "    {\n"
					+ "        Interceptor.attach(incoming_export.address, {\n"
					+ "            onEnter: function(args) {\n"
					+ "                console.log(\"DLOPEN: Entered dlopen related function: \"+incoming_export.name + \", lib to load:\"+args[0].readCString());\n"
					+ "                this.libname=args[0].readCString();\n"
					+ "            },\n"
					+ "            onLeave: function(retval) {\n"
					+ "                console.log(\"DLOPEN: Exited dlopen related function:\"+incoming_export.name+\" ,retval:\"+retval);\n"
					+ "                if (extract_libname_from_dlopen_arg(this.libname)==module_name_"+this.incoming_hook_generator.current_program_name_sanitized+")\n"
					+ "                {\n"
					+ "                    console.log('FOUND LIBRARY THAT HAS JUST BEEN LOADED: '+this.libname+', hooking.');\n"
					+ "                    register_interceptors();\n"
					+ "                }\n"
					+ "            }\n"
					+ "        });\n"
					+ "    } catch (err) { console.log('ERROR: Could not hook function:'+incoming_export.name+' at '+incoming_export.address+','+JSON.stringify(DebugSymbol.fromAddress(incoming_export.address))+', continuing.')}\n"
					+ "}\n"
					+ "\n"
					+ "var process_modules = Process.enumerateModules();\n"
					+ "var we_have_encountered_at_least_one_dlopen=false;\n"
					+ "var we_encountered_the_lib_in_the_initial_pass_of_the_loaded_modules=false;\n"
					+ "for(var i=0;i<process_modules.length;i++){\n"
					+ "\n"
					+ "    if (process_modules[i].name==module_name_"+this.incoming_hook_generator.current_program_name_sanitized+")\n"
					+ "    {\n"
					+ "        console.log(\"The module to register interceptors in, was found already loaded\");\n"
					+ "        we_encountered_the_lib_in_the_initial_pass_of_the_loaded_modules=true;\n"
					+ "        register_interceptors();\n"
					+ "        break;\n"
					+ "    }\n"
					+ "    var exports = process_modules[i].enumerateExports();\n"
					+ "    for(var j=0;j<exports.length;j++)\n"
					+ "    {\n"
					+ "        if (exports[j].name.indexOf(\"dlopen\")>=0) //there may be more than one dlopen related functions, like __libc_dlopen_mode()\n"
					+ "        //if (exports[j].name==\"dlopen\")\n"
					+ "        {\n"
					+ "            console.log(process_modules[i].name);\n"
					+ "            console.log(JSON.stringify(exports[j]));\n"
					+ "            do_the_dlopen_interception(exports[j]);\n"
					+ "            we_have_encountered_at_least_one_dlopen=true;\n"
					+ "        }\n"
					+ "    }\n"
					+ "}\n"
					+ "if (!we_encountered_the_lib_in_the_initial_pass_of_the_loaded_modules && !we_have_encountered_at_least_one_dlopen)\n"
					+ "{\n"
					+ "    console.log(\"DLOPEN: No dlopen found, exiting the frida script...\")\n"
					+ "    throw '';\n"
					+ "}\n"
					+ "\n"
					+ "\n"
					+ "function register_interceptors()\n"
					+ "{\n"
					+ "      console.log(\"Registering interceptors...\");\n"
					+ "      \n\n";
			
		}
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.incoming_hook_generator.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==2)
		{
			//LoadLibrary() method
			hook_str+="var module_name_"+this.incoming_hook_generator.current_program_name_sanitized+"='"+this.incoming_hook_generator.current_program_name+"';\n";
			hook_str+="\n";
			hook_str+="function extract_libname_from_loadlibrary_arg(loadlibrary_arg)\n"
					+ "{\n"
					+ "    if (loadlibrary_arg!==null && loadlibrary_arg.indexOf(\"\\\\\")>=0)\n"
					+ "    {\n"
					+ "        var array_of_subdirs=loadlibrary_arg.split(\"\\\\\");\n"
					+ "        return array_of_subdirs[array_of_subdirs.length-1]; \n"
					+ "    }\n"
					+ "    else\n"
					+ "    {\n"
					+ "        return loadlibrary_arg;\n"
					+ "    }\n"
					+ "}\n"
					+ "\n"
					+ "function do_the_loadlibrary_interception(incoming_export)\n"
					+ "{\n"
					+ "    try "
					+ "    {\n"
					+ "        Interceptor.attach(incoming_export.address, {\n"
					+ "            onEnter: function(args) {\n"
					+ "                if (incoming_export.name.charAt(incoming_export.name.length - 1)==\"A\")\n"
					+ "                {\n"
					+ "                    this.libname=args[0].readAnsiString();\n"
					+ "                }\n"
					+ "                else\n"
					+ "                {\n"
					+ "                    this.libname=args[0].readUtf16String();\n"
					+ "                }\n"
					+ "                console.log(\"LOADLIBRARY: Entered LoadLibrary related function: \"+incoming_export.name + \", lib to load:\"+this.libname);\n"
					+ "\n"
					+ "            },\n"
					+ "            onLeave: function(retval) {\n"
					+ "                console.log(\"LOADLIBRARY: Exited LoadLibrary related function:\"+incoming_export.name+\" ,retval:\"+retval);\n"
					+ "                if (extract_libname_from_loadlibrary_arg(this.libname).toLowerCase()==module_name_"+this.incoming_hook_generator.current_program_name_sanitized+".toLowerCase() || (extract_libname_from_loadlibrary_arg(this.libname)+\".dll\").toLowerCase()==module_name_"+this.incoming_hook_generator.current_program_name_sanitized+".toLowerCase())\n"
					+ "                {\n"
					+ "                    console.log('FOUND LIBRARY THAT HAS JUST BEEN LOADED: '+this.libname+', hooking.');\n"
					+ "                    register_interceptors();\n"
					+ "                }\n"
					+ "            }\n"
					+ "        });\n"
					+ "    } catch (err) { console.log('ERROR: Could not hook function:'+incoming_export.name+' at '+incoming_export.address+','+JSON.stringify(DebugSymbol.fromAddress(incoming_export.address))+', continuing.')}\n"
					+ "}\n"
					+ "\n"
					+ "var process_modules = Process.enumerateModules();\n"
					+ "var we_have_encountered_at_least_one_loadlibrary=false;\n"
					+ "var we_encountered_the_lib_in_the_initial_pass_of_the_loaded_modules=false;\n"
					+ "for(var i=0;i<process_modules.length;i++){\n"
					+ "\n"
					+ "    if (process_modules[i].name.toLowerCase()==module_name_"+this.incoming_hook_generator.current_program_name_sanitized+".toLowerCase() || (process_modules[i].name+\".dll\").toLowerCase()==module_name_"+this.incoming_hook_generator.current_program_name_sanitized+".toLowerCase() )\n"
					+ "    {\n"
					+ "        console.log(\"Encountered the module already loaded\");\n"
					+ "        we_encountered_the_lib_in_the_initial_pass_of_the_loaded_modules=true;\n"
					+ "        register_interceptors();\n"
					+ "        break;\n"
					+ "    }\n"
					+ "    var exports = process_modules[i].enumerateExports();\n"
					+ "    for(var j=0;j<exports.length;j++)\n"
					+ "    {\n"
					+ "        //if (exports[j].name==\"LoadLibrary\")\n"
					+ "        if (exports[j].name.indexOf(\"LoadLibrary\")>=0) //there may be more than one LoadLibrary related functions, like LoadLibraryEx(), LoadLibraryExW(), LoadLibraryExA() ....\n"
					+ "        {\n"
					+ "            console.log(process_modules[i].name);\n"
					+ "            console.log(JSON.stringify(exports[j]));\n"
					+ "            do_the_loadlibrary_interception(exports[j]);\n"
					+ "            we_have_encountered_at_least_one_loadlibrary=true;\n"
					+ "        }\n"
					+ "    }\n"
					+ "}\n"
					+ "if (!we_encountered_the_lib_in_the_initial_pass_of_the_loaded_modules && !we_have_encountered_at_least_one_loadlibrary)\n"
					+ "{\n"
					+ "    console.log(\"LOADLIBRARY: No LoadLibrary found, exiting the frida script...\")\n"
					+ "    throw '';\n"
					+ "}\n"
					+ "\n"
					+ "\n"
					+ "function register_interceptors()\n"
					+ "{\n"
					+ "      console.log(\"Registering interceptors...\");\n"
					+ "      \n\n";
		}
		return hook_str;
		
	}
	
	
	

	protected ArrayList<ContainerForFunctionReferences> handle_outgoing_references_for_one_depth_level(ArrayList<ContainerForFunctionReferences> incoming_functions_from_previous_level,int current_depth)
	{
		int i;
		ArrayList<ContainerForFunctionReferences> retval=new ArrayList<ContainerForFunctionReferences>();
		for (i=0;i<incoming_functions_from_previous_level.size();i++)
		{
			Function newfun=incoming_functions_from_previous_level.get(i).fun;
			Set<Function> called_functions=newfun.getCalledFunctions(null);
			if (called_functions!=null)
			{
				Iterator<Function> iter=called_functions.iterator();
				while (iter.hasNext())
				{
					Function newfun2=iter.next();
					ContainerForFunctionReferences newcontainer=new ContainerForFunctionReferences(newfun2,i,-1,current_depth);
					retval.add(newcontainer);
					if (incoming_functions_from_previous_level.get(i).first_index_of_dest_at_next_depth==-1)
					{
						incoming_functions_from_previous_level.get(i).first_index_of_dest_at_next_depth=retval.size()-1; //fix the container's index at the previous level if it is not set
					}
				}
			}
			
		}
		return retval;
	}
	
	

	//Try to move backwards in the data structure to see the reference path
	String get_outgoing_reference_path_string(ArrayList<ArrayList<ContainerForFunctionReferences>> all_depths_arraylists_of_function_references,int depth,int index_of_container_for_that_depth)
	{
		String retval="";
		
		int tmpdepth=depth;
		int index_of_caller_in_previous_level=index_of_container_for_that_depth;
		while(tmpdepth>=0)
		{
			ContainerForFunctionReferences tmpcontainer=all_depths_arraylists_of_function_references.get(tmpdepth).get(index_of_caller_in_previous_level);
			Function tmpfun=tmpcontainer.fun;
			index_of_caller_in_previous_level=tmpcontainer.index_of_source_at_previous_depth;
			if (tmpdepth>0)
			{
				retval="->".concat(tmpfun.getName(true).replace("\"", "_")).concat(retval);
			}
			else
			{
				retval=tmpfun.getName(true).replace("\"", "_").concat(retval);
			}
			tmpdepth--;
		}
		
		return retval;
	}
	
	

	protected ArrayList<ContainerForFunctionReferences> handle_incoming_references_for_one_depth_level(ArrayList<ContainerForFunctionReferences> called_functions_from_previous_level,int current_depth)
	{
		int i;
		ArrayList<ContainerForFunctionReferences> retval=new ArrayList<ContainerForFunctionReferences>();
		for (i=0;i<called_functions_from_previous_level.size();i++)
		{
			Function newfun=called_functions_from_previous_level.get(i).fun;
			Set<Function> calling_functions=newfun.getCallingFunctions(null);
			if (calling_functions!=null)
			{
				Iterator<Function> iter=calling_functions.iterator();
				while (iter.hasNext())
				{
					Function newfun2=iter.next();
					ContainerForFunctionReferences newcontainer=new ContainerForFunctionReferences(newfun2,i,-1,current_depth);
					retval.add(newcontainer);
					if (called_functions_from_previous_level.get(i).first_index_of_dest_at_next_depth==-1)
					{
						called_functions_from_previous_level.get(i).first_index_of_dest_at_next_depth=retval.size()-1; //fix the container's index at the previous level if it is not set
					}
				}
			}
			
		}
		return retval;
	}
	

	//Try to move backwards in the data structure to see the reference path
	String get_incoming_reference_path_string(ArrayList<ArrayList<ContainerForFunctionReferences>> all_depths_arraylists_of_function_references,int depth,int index_of_container_for_that_depth)
	{
		String retval="";
		
		int tmpdepth=depth;
		int index_of_callee_in_previous_level=index_of_container_for_that_depth;
		while(tmpdepth>=0)
		{
			ContainerForFunctionReferences tmpcontainer=all_depths_arraylists_of_function_references.get(tmpdepth).get(index_of_callee_in_previous_level);
			Function tmpfun=tmpcontainer.fun;
			index_of_callee_in_previous_level=tmpcontainer.index_of_source_at_previous_depth;
			if (tmpdepth == depth)
			{
				retval=retval.concat(tmpfun.getName(true).replace("\"", "_"));
			}
			else
			{
				retval=retval.concat("->").concat(tmpfun.getName(true).replace("\"", "_"));
			}
			tmpdepth--;
		}
		
		return retval;
	}
	
	protected Boolean user_options_allow_printing_of_params()
	{
		if (this.incoming_hook_generator.isAdvanced)
		{
			return (!this.incoming_hook_generator.advancedhookoptionsdialog.isDoNotIncludeFunParamscheckboxchecked);
		}
		return true;
	}
	
	protected void interpret_user_custom_options_on_function_hook_generation()
	{
		if (!this.incoming_hook_generator.isAdvanced || (this.incoming_hook_generator.isAdvanced && !this.incoming_hook_generator.advancedhookoptionsdialog.isCustomFunInterceptorHookOutputCheckboxchecked)) 
		{
			this.incoming_hook_generator.include_onEnter_in_function_hooks=true;
			this.incoming_hook_generator.include_onLeave_in_function_hooks=true;
			this.incoming_hook_generator.use_interceptor_attach_instead_of_replace_in_function_hooks=true;
			return;
		}
		if (this.incoming_hook_generator.advancedhookoptionsdialog.CustomFunInterceptorHookOutputcomboBox.getSelectedIndex()==0)
		{
			this.incoming_hook_generator.include_onEnter_in_function_hooks=false;
		}
		if (this.incoming_hook_generator.advancedhookoptionsdialog.CustomFunInterceptorHookOutputcomboBox.getSelectedIndex()==1)
		{
			this.incoming_hook_generator.include_onLeave_in_function_hooks=false;
		}
		if (this.incoming_hook_generator.advancedhookoptionsdialog.CustomFunInterceptorHookOutputcomboBox.getSelectedIndex()==2)
		{
			this.incoming_hook_generator.use_interceptor_attach_instead_of_replace_in_function_hooks=false;
		}
	}

	String generate_try_catch_text_before_interceptor_hook()
	{
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isIncludeInterceptorTryCatchcheckboxchecked)
		{
			return "try { ";
		}
		return "";
	}
	
	String generate_try_catch_text_after_interceptor_hook(Address addr)
	{
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isIncludeInterceptorTryCatchcheckboxchecked)
		{
			return " counter_for_successful_Interceptor_hooks++;} catch(error) { counter_for_failed_Interceptor_hooks++; console.log('Error_'+counter_for_failed_Interceptor_hooks+': Could not hook address "+addr+"') }";
		}
		return "";
	}
	
	String populate_data_structures_that_link_addresses_and_function_names(String spaces,String current_addr_js_variable,String current_function_name_sanitized,Function current_function)
	{
		String retval="";
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isCreateDataStructuresToLinkAddressesAndFunctionNamescheckboxchecked)
		{
			retval+=spaces+"dict_from_current_addresses_to_function_names["+current_addr_js_variable+"]=\""+current_function_name_sanitized+"\";\n";
			if (!current_function_name_sanitized.equals("not in a function") && current_function!=null)
			{
				retval+=spaces+"current_function_start_address=Module.findBaseAddress(module_name_"+this.incoming_hook_generator.current_program_name_sanitized+").add(0x"+Long.toHexString(current_function.getEntryPoint().getOffset()-this.incoming_hook_generator.image_base.getOffset())+");\n";
				retval+=spaces+"dict_from_function_names_to_function_start_addresses[\""+current_function_name_sanitized+"\"]=current_function_start_address;\n";
				retval+=spaces+"dict_from_current_addresses_to_function_start_addresses["+current_addr_js_variable+"]=current_function_start_address;\n";
				retval+=spaces+"dict_from_function_start_addresses_to_function_names[current_function_start_address]=\""+current_function_name_sanitized+"\";\n";
			}
		}
		return retval;
	}
	
	
	

	
	protected String get_frida_nativefun_str_for_parameter(DataType param_datatype)
	{
		/* it is assumed that the input parameter has been checked to not be null*/
		String str_for_param="";
		int this_param_size=param_datatype.getLength();
		if (param_datatype.toString().indexOf(" *")>=0)
		{
			//pointer
			str_for_param+="'pointer'";
		}
		else if (param_datatype.toString()=="double")
		{
			str_for_param+="'double'";
		}
		else if (param_datatype.toString()=="float")
		{
			str_for_param+="'float'";
		}
		else if (param_datatype.toString()=="int")
		{
			str_for_param+="'int'";
		}
		else if (param_datatype.toString()=="long")
		{
			str_for_param+="'long'";
		}
		else
		{
			str_for_param+="'int"+this_param_size*8+"'"; //it is assumed that the size is checked to be in an accepted range
		}
		return str_for_param;
	}
	
	

	/*Any errors are returned with the hook str*/
	protected String identify_errors_if_interceptor_replace_is_used(Function current_function,int parameter_count)
	{
		String hook_str="";
		
		if (this.incoming_hook_generator.use_interceptor_attach_instead_of_replace_in_function_hooks)
		{
			return "";
		}
		if (current_function.hasVarArgs())
		{
			hook_str=hook_str.concat("      //Current function has variadic number of arguments, interceptor.replace not supported yet\n");
			return hook_str;
		}
		if (current_function.getReturnType()==null)
		{
			hook_str=hook_str.concat("      //Current function has undefined type of return value\n");
			return hook_str;
		}
		
		int size_of_returntype=current_function.getReturnType().getLength();
		//void is not ZeroLength, but getLength returns 0
		if (current_function.getReturnType().isZeroLength() || (current_function.getReturnType().toString()!="void" && size_of_returntype!=1 && size_of_returntype!=2 && size_of_returntype!=4 && size_of_returntype!=8)  )
		{
			hook_str=hook_str.concat("      //Current function has an unaccepted return type:"+current_function.getReturnType().toString()+"\n");
			return hook_str;
		}
		
		
		//check if the parameter sizes are valid
		Boolean all_param_sizes_are_valid=true;
		for (int i=0;i<parameter_count;i++)
		{
			int param_size=current_function.getParameter(i).getDataType().getLength();
			if (current_function.getParameter(i).getDataType().isZeroLength() || (param_size!=1 && param_size!=2 && param_size!=4 && param_size!=8))
			{
				all_param_sizes_are_valid=false;
				hook_str=hook_str.concat("      //Current function cannot be Interceptor.replace()'d as parameter at position "+i+" has size "+param_size+"\n");
				break;
			}
		}
		return hook_str;
	}
	
	
	

	
	/* This function tries to predict, whether there might be a future reason for hooking the current address, for which special treatment (code that may later be needed to be added) is required.
	 * For example, if the current address is about a dynamic call instruction, then maybe, a later hook for the same address is asked to print the where the code will go.
	 * As the hook string is generated only once, that string will have to put a placeholder for the code that does the "special treatment". 
	 * This function only checks whether there is any chance that the current instruction may need a "special treatment" by iterating over all the implemented reasons for "special treatment", and checking if they may apply.
	 */
	protected Boolean can_there_be_any_reason_why_this_address_may_need_code_that_is_later_added_in_the_hook(Address addr)
	{
		if (this.incoming_hook_generator.isAdvanced && (this.incoming_hook_generator.advancedhookoptionsdialog.isOutDynamicCallReferencesfromFunctionCheckBoxchecked || this.incoming_hook_generator.advancedhookoptionsdialog.isOutDynamicCallReferencesfromAddressCheckBoxchecked))
		{
			Instruction current_instruction=this.incoming_hook_generator.current_program_listing.getInstructionAt(addr);
			if (current_instruction!=null && current_instruction.getFlowType().isComputed())// && current_instruction.getFlowType().isCall()) //Uncomment to restrict selection to computed hooks, do the same below
			{	
				String current_instruction_str_lowercase=current_instruction.toString().toLowerCase().trim();
				String current_instruction_mnemonic=current_instruction.getMnemonicString().toLowerCase().trim();
				if (this.incoming_hook_generator.current_program_language.getLanguageID().toString().indexOf("x86:LE:64")>=0 && 
						(current_instruction_mnemonic.equals("call") || current_instruction_mnemonic.equals("jmp"))
					)
				{
					return true;
				}
				
				if (this.incoming_hook_generator.current_program_language.getLanguageID().toString().indexOf("AARCH64:LE:64")>=0 && 
						(current_instruction_mnemonic.equals("blr") || current_instruction_mnemonic.equals("bx") ||
						 current_instruction_mnemonic.equals("br") || current_instruction_mnemonic.equals("blraaz") ||
						 current_instruction_mnemonic.equals("blrabz") )
					)
				{
					return true;
				}
			}
		}
		return false;
	}
	
	/*Used for efficiency*/
	protected Boolean is_there_a_chance_that_some_hooks_generated_in_the_current_batch_require_code_that_is_later_added_in_the_hook()
	{
		if (this.incoming_hook_generator.isAdvanced && (this.incoming_hook_generator.current_program_language.getLanguageID().toString().indexOf("x86:LE:64")>=0 || this.incoming_hook_generator.current_program_language.getLanguageID().toString().indexOf("AARCH64:LE:64")>=0) && 
				(this.incoming_hook_generator.advancedhookoptionsdialog.isOutDynamicCallReferencesfromAddressCheckBoxchecked || this.incoming_hook_generator.advancedhookoptionsdialog.isOutDynamicCallReferencesfromFunctionCheckBoxchecked))
		{
			return true;
		}
		return false;
	}
		
	protected Boolean does_the_current_instruction_definitely_need_hook_code_to_also_be_added_later(Instruction current_instruction,String reason_for_hook_generation)
	{
		if (this.incoming_hook_generator.isAdvanced && current_instruction!=null && current_instruction.getFlowType().isComputed())// && current_instruction.getFlowType().isCall()) //Uncomment to restrict selection to computed hooks, do the same above
		{
			if (this.incoming_hook_generator.advancedhookoptionsdialog.isOutDynamicCallReferencesfromAddressCheckBoxchecked || (this.incoming_hook_generator.advancedhookoptionsdialog.isOutDynamicCallReferencesfromFunctionCheckBoxchecked && reason_for_hook_generation.indexOf("containing a dynamic (computed) call/jump")>=0))
			{
				String current_instruction_str_lowercase=current_instruction.toString().toLowerCase().trim();
				String current_instruction_mnemonic=current_instruction.getMnemonicString().toLowerCase().trim();
				
				if (this.incoming_hook_generator.current_program_language.getLanguageID().toString().indexOf("x86:LE:64")>=0 && 
						(current_instruction_mnemonic.equals("call") || current_instruction_mnemonic.equals("jmp"))
					)
					
				{
					return true;
				}
				
				if (this.incoming_hook_generator.current_program_language.getLanguageID().toString().indexOf("AARCH64:LE:64")>=0 && 
						(current_instruction_mnemonic.equals("blr") || current_instruction_mnemonic.equals("bx") ||
						 current_instruction_mnemonic.equals("br") || current_instruction_mnemonic.equals("blraaz") ||
						 current_instruction_mnemonic.equals("blrabz") )
					)
				{
					return true;
				}
			}
		}
		return false;
	}
	
	
	protected void update_internal_data_structures(Address addr,String hook_str, String reason_for_hook_generation)
	{
		this.incoming_hook_generator.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch++;
		String tmpstr=String.valueOf(this.incoming_hook_generator.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch)+"|"+reason_for_hook_generation;
		this.incoming_hook_generator.internal_structures_for_hook_generation.Addresses_for_current_hook_str.put(addr.toString(),tmpstr); //this is the initial placement of this address in the Addresses_for_current_hook_str data structure
		this.incoming_hook_generator.internal_structures_for_hook_generation.addresses_for_which_hook_is_generated_in_order_of_appearance.add(addr);
		this.incoming_hook_generator.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.add(hook_str);
		//if it fills the prerequisites for code to be added later, then update the Addresses_that_need_hook_code_to_be_added_at_a_later_stage
		if (this.incoming_hook_generator.isAdvanced && can_there_be_any_reason_why_this_address_may_need_code_that_is_later_added_in_the_hook(addr)) //first check
		{
			Instruction current_instruction=this.incoming_hook_generator.current_program_listing.getInstructionAt(addr);
			//Check for computed calls/jumps . This time we need to be certain that this address is supposed to contain code related to computed calls/jumps
			if (current_instruction!=null && does_the_current_instruction_definitely_need_hook_code_to_also_be_added_later(current_instruction,reason_for_hook_generation))
			{			
				HashMap<String,String> tmphm= new HashMap<String,String>();
				String reason_for_computed_call_or_jump="";
				if (this.incoming_hook_generator.current_program_listing.getFunctionContaining(addr)!=null && this.incoming_hook_generator.current_program_listing.getFunctionContaining(addr).getEntryPoint()==addr)
				{
					reason_for_computed_call_or_jump="start of function";
				}
				{
					reason_for_computed_call_or_jump="simple instruction";	
				}
				tmphm.put("Computed Call/Jump",reason_for_computed_call_or_jump);
				if (!this.incoming_hook_generator.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.containsKey(addr))
				{
					this.incoming_hook_generator.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.put(addr,tmphm );
				}
				else
				{
					//see if this address has already been registered as "Computed Call/Jump"
					if (this.incoming_hook_generator.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.get(addr).containsKey("Computed Call/Jump"))
					{
						;//do nothing, it's already registered
					}
					else
					{
						this.incoming_hook_generator.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.get(addr).put("Computed Call/Jump",reason_for_computed_call_or_jump);
					}
				}
			}
		}
	}
	
	protected String format_reason_for_hooking(String unformatted_reason)
	{
		String[] individual_reasons=unformatted_reason.split("\\|");
		int i;
		String retval="";
		int max_reasons_to_show=this.incoming_hook_generator.maximum_number_of_reasons_to_show;
		//starting from 1 as the first is not the reason, but the order of address, that is the increasing counter when it first appeared
		for (i=1;i<individual_reasons.length;i++)
		{
			if (i<=max_reasons_to_show)
			{
				retval=retval.concat(individual_reasons[i]);
				if (i<individual_reasons.length-1) //we haven't reached the end
				{
					retval=retval.concat("   ###   ");
				}
			}
			else
			{
				retval=retval.concat(", ... ");
				break;
			}
		}
		return retval;
	}
	
	
	

	
	protected void backpatch_reasons_for_advanced_hook_generation()
	{
		if (this.incoming_hook_generator.advancedhookoptionsdialog.isOutputReasonForHookGenCheckboxchecked)
		{
			this.incoming_hook_generator.maximum_number_of_reasons_to_show=Integer.parseInt(this.incoming_hook_generator.advancedhookoptionsdialog.ReasonForHookGenAmountcomboBox.getItemAt(this.incoming_hook_generator.advancedhookoptionsdialog.ReasonForHookGenAmountcomboBox.getSelectedIndex()));

			if (this.incoming_hook_generator.incoming_monitor.isCancelled()) {return ;} //check for cancellation by the user)
			this.incoming_hook_generator.incoming_monitor.setMessage("Backpatching reasons in hooks...");
			/*
			 * If that is the case, then the hook_str only has the prologue, as every other hook returned the empty string or a comment.
			 * Now it is time to go through all the hooks in the internal data structures and patch the reasons why they were hooked
			 */
			int i;
			for (i=0;i<this.incoming_hook_generator.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch;i++)
			{
				Address current_addr =this.incoming_hook_generator.internal_structures_for_hook_generation.addresses_for_which_hook_is_generated_in_order_of_appearance.get(i);
				String current_hook_for_addr=this.incoming_hook_generator.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.get(i);
				String reason_str_for_current_hook=this.incoming_hook_generator.internal_structures_for_hook_generation.Addresses_for_current_hook_str.get(current_addr.toString());
				String formatted_reason_str_for_current_hook=format_reason_for_hooking(reason_str_for_current_hook);
				this.incoming_hook_generator.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.set(i,current_hook_for_addr.replace("PLACEHOLDER_FOR_REASONS_FOR_HOOKING_"+current_addr,formatted_reason_str_for_current_hook));
			
				if (i%100==0 && this.incoming_hook_generator.incoming_monitor.isCancelled()) {return ;} //check for cancellation by the user
				if (i%1000==0) {this.incoming_hook_generator.incoming_monitor.setMessage("Backpatching reasons in hooks "+(int)((i*100)/this.incoming_hook_generator.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch)+"%...");}
			}
		}
		if (this.incoming_hook_generator.consoleService!=null)
		{
			this.incoming_hook_generator.consoleService.println("// Backpatching reasons completed");
		}
	}
	

	/*This function, effectively adds the code*/
	protected void backpatch_hooks_that_need_code_to_be_added_at_a_later_stage()
	{
		if (this.incoming_hook_generator.incoming_monitor.isCancelled()) {return;} //check for cancellation by the user)
		this.incoming_hook_generator.incoming_monitor.setMessage("Backpatching hooks that need more code...");
		
		int i;
		for (i=0;i<this.incoming_hook_generator.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch;i++)
		{
			Address newaddr=this.incoming_hook_generator.internal_structures_for_hook_generation.addresses_for_which_hook_is_generated_in_order_of_appearance.get(i);
			if (this.incoming_hook_generator.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.containsKey(newaddr))
			{
				
				
				Instruction newinstr=this.incoming_hook_generator.current_program_listing.getInstructionAt(newaddr);
				//newinstr will necessarily be not null, as a hook is supposed to be generated for it
				String current_hook_for_addr=this.incoming_hook_generator.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.get(i);
				String hook_to_replace_later_code_placeholder="";
				
				for (String reason: this.incoming_hook_generator.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.get(newaddr).keySet())
				{
					if (reason=="Computed Call/Jump")
					{
						String options_for_computed_call_or_jump = this.incoming_hook_generator.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.get(newaddr).get(reason);
						String spaces="";
						if (options_for_computed_call_or_jump=="simple instruction")
						{
							spaces="          ";
						}
						else
						{
							//options_for_computed_call_or_jump=="start of function"
							spaces="                      ";
						}
						String arg_of_call=newinstr.toString().split(" ",2)[1].toLowerCase().trim();  //remove of CALL/BLR... and get the rest, the argument
						String mnemonic_of_command=newinstr.getMnemonicString().toLowerCase().trim();
						ComputedCallHookGenerator hookgenerator=new ComputedCallHookGenerator(this.incoming_hook_generator.current_program,newaddr,mnemonic_of_command,arg_of_call,"module_name_"+this.incoming_hook_generator.current_program_name_sanitized);
						hook_to_replace_later_code_placeholder=hook_to_replace_later_code_placeholder.concat(hookgenerator.provide_hook_code(spaces));
					}
					//Other possible reasons can go here
				}

				this.incoming_hook_generator.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.set(i,current_hook_for_addr.replace("PLACEHOLDER_FOR_HOOK_CODE_TO_BE_ADDED_LATER_"+newaddr,hook_to_replace_later_code_placeholder));
				
				
				if (i%100==0 && this.incoming_hook_generator.incoming_monitor.isCancelled()) {return ;} //check for cancellation by the user
				if (i%1000==0) {this.incoming_hook_generator.incoming_monitor.setMessage("Backpatching hooks that need more code "+(int)((i*100)/this.incoming_hook_generator.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch)+"%...");}
			}
		}
				
	}
	
	
	
	

	
	protected String generate_backtrace_for_hook(Boolean called_from_function_start)
	{
		String hook_str="";
		String bt="";
		String ctx="";
		String spaces="";
		
		if (!this.incoming_hook_generator.isAdvanced || !this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateBacktraceCheckboxchecked)
		{
			return "";
		}
		if ((this.incoming_hook_generator.advancedhookoptionsdialog.GenerateBacktracecomboBox.getSelectedIndex()==0 
				|| this.incoming_hook_generator.advancedhookoptionsdialog.GenerateBacktracecomboBox.getSelectedIndex()==1)
				&& !called_from_function_start)
		{
			return "";
		}
		
		if (called_from_function_start)
		{
			ctx="this.context";
			spaces="                      ";
		}
		else
		{ 
			ctx="null";
			spaces="          ";
		}

		if (this.incoming_hook_generator.advancedhookoptionsdialog.GenerateBacktracecomboBox.getSelectedIndex()==0
			|| this.incoming_hook_generator.advancedhookoptionsdialog.GenerateBacktracecomboBox.getSelectedIndex()==2)
		{
			bt="Backtracer.ACCURATE";
		}
		if (this.incoming_hook_generator.advancedhookoptionsdialog.GenerateBacktracecomboBox.getSelectedIndex()==1
				|| this.incoming_hook_generator.advancedhookoptionsdialog.GenerateBacktracecomboBox.getSelectedIndex()==3)
		{
			bt="Backtracer.FUZZY";
		}
		
		hook_str=hook_str.concat(spaces+"console.log(\"Backtrace:\"+");
		hook_str=hook_str.concat("Thread.backtrace("+ctx+", "+bt+")"
								+ ".map(DebugSymbol.fromAddress).join('\\n') + '\\n');\n");
		return hook_str;
	}
	
	
	
	
	
}
