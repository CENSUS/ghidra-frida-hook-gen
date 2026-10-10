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
import java.util.Random;
import java.util.Set;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

/*
 * Sister class of HookGenerator, containing many useful functions that are called sometime in its code. 
 * It receives a reference to it and uses its internal variables.
 */
 
public class HookGeneratorUtils {

	private HookGenerator incoming_hook_generator;
	/*
	 * The characters that a name of the generated javascript may be made of. There is one definition of it, and HookGenerator
	 * reads it from here, because two copies of a list like this drift and the two of them together decide which names the
	 * script carries.
	 */
	public static final String characters_allowed_in_variable_name="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
	/*The address of the hook is appended to this, and the result is put inside the hook, to be replaced when the hooks are backpatched. It is kept here so that the places that write it and the places that look for it can never disagree*/
	protected static final String prefix_of_placeholder_for_hook_code_to_be_added_later="PLACEHOLDER_FOR_HOOK_CODE_TO_BE_ADDED_LATER_";

	public HookGeneratorUtils(HookGenerator incoming_hook_generator)
	{
		this.incoming_hook_generator = incoming_hook_generator;
	}
	

	/*
	 * Returns the javascript function that compares the name of a module with the name of the program, deciding at runtime,
	 * from Process.platform, how that comparison has to be made. Every prologue that needs to recognize the module emits it.
	 *
	 * Careful: the tolerance that Windows needs must not be handed out to every platform. In Windows the names of the
	 * modules are not case sensitive and the .dll suffix is not always part of the name. On the systems where dlopen() is
	 * the loader the file names ARE case sensitive and a library is not a .dll, so the very same tolerance would be harmful
	 * there: it would let libFoo.so match libfoo.so, which is a different file, and the hooks would end up in the wrong
	 * library. The decision is taken at runtime and not from the format of the analyzed file, because what matters is the
	 * platform the script is running on.
	 */
	protected String return_javascript_function_that_compares_module_names()
	{
		String name_of_program=this.incoming_hook_generator.current_program_name_sanitized;
		return "/*The name of the module is compared the way that the platform the script runs on compares it*/\n"
				+ "function does_module_name_match_the_wanted_one_"+name_of_program+"(name_of_module)\n"
				+ "{\n"
				+ "    if (name_of_module===null || name_of_module===undefined) { return false; }\n"
				+ "    if (Process.platform==='windows')\n"
				+ "    {\n"
				+ "        //in Windows the names of the modules are not case sensitive, and the .dll suffix is not always part of the name\n"
				+ "        return (name_of_module.toLowerCase()===module_name_"+name_of_program+".toLowerCase() || (name_of_module+'.dll').toLowerCase()===module_name_"+name_of_program+".toLowerCase() || name_of_module.toLowerCase()===(module_name_"+name_of_program+"+'.dll').toLowerCase());\n"
				+ "    }\n"
				+ "    //everywhere else the names of the libraries are case sensitive, and a library is not a .dll\n"
				+ "    return (name_of_module===module_name_"+name_of_program+");\n"
				+ "}\n"
				+ "\n";
	}


	protected String generate_epilogue_for_address(Address addr, Boolean print_debug) {
		
		String hook_str="";
		
		if (!this.incoming_hook_generator.isAdvanced || (this.incoming_hook_generator.isAdvanced && !this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked) || (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.incoming_hook_generator.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==0))
		{
			//default method
			hook_str+="        \n";
			hook_str+="        Interceptor.flush();\n"
					+ "        console.log(\"Registered interceptors.\");\n"
					+ "    }, 2000);//milliseconds\n"
					+ "}\n"
					+ "start_timer_for_intercept();\n";
		}
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.incoming_hook_generator.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==1 ||
				this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.incoming_hook_generator.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==2 ||
				this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.incoming_hook_generator.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==3 )
		{
			//dlopen(), LoadLibrary() or attachModuleObserver() method
			hook_str+="        \n"
					+ "    Interceptor.flush();\n"
					+ "    console.log(\"Registered interceptors.\");\n"
					+ "}\n";
		}
		
		return hook_str;
				
	}
	
	
	protected String generate_prologue_for_address(Address addr, Boolean print_debug) {
		
		String hook_str="";
		
		if (!this.incoming_hook_generator.isAdvanced || (this.incoming_hook_generator.isAdvanced && !this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked) || (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.incoming_hook_generator.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==0))
		{
			//default method
			hook_str+="var module_name_"+this.incoming_hook_generator.current_program_name_sanitized+"='"+return_string_escaped_for_a_javascript_string_literal(this.incoming_hook_generator.current_program_name)+"';\n";
			hook_str+="\n";
			hook_str+="function start_timer_for_intercept() {\n"
					+ "  setTimeout(\n"
					+ "    function() {\n"
					+ "        console.log(\"Registering interceptors...\");\n";
			hook_str+="        \n";
			hook_str+="        \n";
		}
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.incoming_hook_generator.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==1)
		{
			//dlopen() method
			hook_str+="var module_name_"+this.incoming_hook_generator.current_program_name_sanitized+"='"+return_string_escaped_for_a_javascript_string_literal(this.incoming_hook_generator.current_program_name)+"';\n";
			hook_str+="\n";
			/*dlopen() is the loader of the systems where the file names are case sensitive and a library is not a .dll, and the function below is what keeps that distinction*/
			hook_str+=return_javascript_function_that_compares_module_names();
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
					+ "    try \n"
					+ "    {\n"
					+ "        Interceptor.attach(incoming_export.address, {\n"
					+ "            onEnter: function(args) {\n"
					+ "                console.log(\"DLOPEN: Entered dlopen related function: \"+incoming_export.name + \", lib to load:\"+args[0].readCString());\n"
					+ "                this.libname=args[0].readCString();\n"
					+ "            },\n"
					+ "            onLeave: function(retval) {\n"
					+ "                console.log(\"DLOPEN: Exited dlopen related function:\"+incoming_export.name+\" ,retval:\"+retval);\n"
					/*Careful: the comparison is exact on purpose. dlopen() is the loader of the systems where the names of the libraries are case sensitive and where a library is never a .dll . Windows is not handled here at all, it has its own LoadLibrary() method*/
					+ "                if (does_module_name_match_the_wanted_one_"+this.incoming_hook_generator.current_program_name_sanitized+"(extract_libname_from_dlopen_arg(this.libname)))\n"
					+ "                {\n"
					+ "                    console.log('FOUND LIBRARY THAT HAS JUST BEEN LOADED: '+this.libname+', hooking.');\n"
					+ "                    //Process.getModuleByName(module_name_"+this.incoming_hook_generator.current_program_name_sanitized+").ensureInitialized();   //uncomment to make sure the initializers of the module have run before it is hooked. The loader runs them before it returns, so this only confirms it, and we are still inside the loader call here\n"
					+ "                    register_interceptors();\n"
					+ "                    //setTimeout(register_interceptors,0);   //enable this one instead of the line above if the hooking hangs the program: it leaves the loader and does the hooking on the main javascript thread of frida. Careful: the module runs for a moment before the hooks are in place, so the earliest calls can be missed\n"
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
					/*Careful: exact comparison here as well, for the same reason. This is the dlopen() method, not the LoadLibrary() one*/
					+ "    if (does_module_name_match_the_wanted_one_"+this.incoming_hook_generator.current_program_name_sanitized+"(process_modules[i].name))\n"
					+ "    {\n"
					+ "        console.log(\"The module to register interceptors in, was found already loaded\");\n"
					+ "        we_encountered_the_lib_in_the_initial_pass_of_the_loaded_modules=true;\n"
					+ "        //Process.getModuleByName(module_name_"+this.incoming_hook_generator.current_program_name_sanitized+").ensureInitialized();   //uncomment to make sure the initializers of the module have run before it is hooked. It was already loaded when the script attached, so they have\n"
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
					+ "    console.log(\"Registering interceptors...\");\n"
					+ "    \n\n";
			
		}
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.incoming_hook_generator.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==2)
		{
			//LoadLibrary() method
			hook_str+="var module_name_"+this.incoming_hook_generator.current_program_name_sanitized+"='"+return_string_escaped_for_a_javascript_string_literal(this.incoming_hook_generator.current_program_name)+"';\n";
			hook_str+="\n";
			/*Every comparison of a module name goes through this one function, so that the tolerance that Windows needs exists in exactly one place and is applied only there*/
			hook_str+=return_javascript_function_that_compares_module_names();
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
					/*Careful: readAnsiString()/readUtf16String() can return null, so the name must never be lowercased on the spot. The comparison function checks for that before it touches the name*/
					+ "                if (does_module_name_match_the_wanted_one_"+this.incoming_hook_generator.current_program_name_sanitized+"(extract_libname_from_loadlibrary_arg(this.libname)))\n"
					+ "                {\n"
					+ "                    console.log('FOUND LIBRARY THAT HAS JUST BEEN LOADED: '+this.libname+', hooking.');\n"
					+ "                    //Process.getModuleByName(module_name_"+this.incoming_hook_generator.current_program_name_sanitized+").ensureInitialized();   //uncomment to make sure the initializers of the module have run before it is hooked. The loader runs them before it returns, so this only confirms it, and we are still inside the loader call here\n"
					+ "                    register_interceptors();\n"
					+ "                    //setTimeout(register_interceptors,0);   //enable this one instead of the line above if the hooking hangs the program: it leaves the loader and does the hooking on the main javascript thread of frida. Careful: the module runs for a moment before the hooks are in place, so the earliest calls can be missed\n"
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
					+ "    if (does_module_name_match_the_wanted_one_"+this.incoming_hook_generator.current_program_name_sanitized+"(process_modules[i].name))\n"
					+ "    {\n"
					+ "        console.log(\"Encountered the module already loaded\");\n"
					+ "        we_encountered_the_lib_in_the_initial_pass_of_the_loaded_modules=true;\n"
					+ "        //Process.getModuleByName(module_name_"+this.incoming_hook_generator.current_program_name_sanitized+").ensureInitialized();   //uncomment to make sure the initializers of the module have run before it is hooked. It was already loaded when the script attached, so they have\n"
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
					+ "    console.log(\"Registering interceptors...\");\n"
					+ "    \n\n";
		}
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateScriptCheckboxchecked && this.incoming_hook_generator.advancedhookoptionsdialog.TypeofScriptGenerationcomboBox.getSelectedIndex()==3)
		{
			//attachModuleObserver method
			String varstr_for_observer=this.generate_random_string_from_pool(characters_allowed_in_variable_name,6);
			hook_str+="var module_name_"+this.incoming_hook_generator.current_program_name_sanitized+"='"+return_string_escaped_for_a_javascript_string_literal(this.incoming_hook_generator.current_program_name)+"';\n";
			hook_str+="\n";
			/*
			 * Unlike the dlopen() and the LoadLibrary() methods, which each belong to one family of systems, the module
			 * observer runs everywhere. The comparison of the name is therefore made to suit the system that the script
			 * runs on, instead of being written for one of them.
			 */
			hook_str+=return_javascript_function_that_compares_module_names();
			hook_str+="var observer_"+varstr_for_observer+" = Process.attachModuleObserver({\n"
					+ "    onAdded(module) {\n"
					+ "        console.log('Module '+module.path+' was just loaded, with base address: '+module.base);\n"
					+ "        if (does_module_name_match_the_wanted_one_"+this.incoming_hook_generator.current_program_name_sanitized+"(module.name))\n"
					+ "        {\n"
					+ "            console.log('Found our module!');\n"
					+ "            //Process.getModuleByName(module_name_"+this.incoming_hook_generator.current_program_name_sanitized+").ensureInitialized();   //uncomment to make sure the initializers of the module have run before it is hooked. This callback can arrive before they do, so this is the method where it matters. Careful: forcing them runs code of the target from inside the loader, which can deadlock\n"
					+ "            intercept_identified_module_"+this.incoming_hook_generator.current_program_name_sanitized+"();\n"
					+ "            //setTimeout(intercept_identified_module_"+this.incoming_hook_generator.current_program_name_sanitized+",0);   //enable this one instead of the line above if the hooking hangs the program: it leaves the loader and does the hooking on the main javascript thread of frida. Careful: the module runs for a moment before the hooks are in place, so the earliest calls can be missed\n"
					+ "        }\n"
					+ "    },\n"
					+ "    onRemoved(module) {\n"
					+ "        console.log('Module '+module.path+' was  unloaded');\n"
					+ "    }\n"
					+ "});"
					+ "\n"
					+ "\n"
					+ "function intercept_identified_module_"+this.incoming_hook_generator.current_program_name_sanitized+"()\n"
					+ "{\n"
					+ "    console.log(\"Registering interceptors...\");\n";
			hook_str+="    \n";
			hook_str+="    \n";
		}
		
		return hook_str;
		
		
		
	}
	
	
	protected String return_code_for_initialization_of_functions_and_variables_before_the_hooks()
	{
		String retval="";

		/*
		 * Careful: the base of the module is deliberately NOT resolved once here and shared by all the hooks. Every hook
		 * resolves it on its own, so that each one of them stays a self contained piece of code that can be copied out on
		 * its own and pasted anywhere, which is the whole point of the snippets.
		 */

		//If we have many try/catch blocks, we should calculate the successes/failures and print them in the end
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isIncludeInterceptorTryCatchcheckboxchecked)
		{
			retval+="        var counter_for_successful_Interceptor_hooks=0;\n";
			retval+="        var counter_for_failed_Interceptor_hooks=0;\n";
			retval+="\n";
		}
		
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isCreateDataStructuresToLinkAddressesAndFunctionNamescheckboxchecked)
		{
			retval += "        var dict_from_current_addresses_to_function_names={}\n"
					+ "        var dict_from_function_names_to_function_start_addresses={}\n"
					+ "        var dict_from_current_addresses_to_function_start_addresses={}\n"
					+ "        var dict_from_function_start_addresses_to_function_names={}\n"
					+ "        var current_function_start_address=ptr(\"0x0\")\n"
					+ "        /*\n"
					+ "        access with: \n"
					+ "            var current_function_name=dict_from_current_addresses_to_function_names[this.context.pc]\n"
					+ "        check if current address is at the start of the function: \n"
					+ "            var is_current_addr_the_start_of_the_current_function=false;\n"
					+ "            if (this.context.pc in dict_from_current_addresses_to_function_start_addresses && dict_from_current_addresses_to_function_start_addresses[this.context.pc].equals(this.context.pc))\n"
					+ "            {\n"
					+ "                is_current_addr_the_start_of_the_current_function=true;\n"
					+ "            }  \n"
					+ "        */\n\n";
		}
		
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isCreateDataStructureWithInterceptorAttachObjectscheckboxchecked)
		{
			retval += "        var dict_with_objects_returned_from_attach={}\n\n";
		}

		/*The hooks of the computed calls/jumps need a ModuleMap in order to find where their destination belongs. It is created once here, instead of being rebuilt on every single call through every hooked instruction*/
		if (is_there_a_chance_that_some_hooks_generated_in_the_current_batch_require_code_that_is_later_added_in_the_hook())
		{
			retval += "        var modulemap_for_all_modules=new ModuleMap();\n\n";
		}
		
		
		//handling the case where threadID and indentation are requested
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isIncludeTIDAndIndentationcheckboxchecked)
		{
			retval += "        var dict_with_thread_indentation_levels={}\n"
					+ "        function tid_and_indent(thiz) {\n"
					+ "            var current_threadid=Process.getCurrentThreadId()\n"
					+ "            if (current_threadid in dict_with_thread_indentation_levels) {\n"
					+ "                return ('TID '+current_threadid+': ').padEnd(14)+dict_with_thread_indentation_levels[current_threadid]+'('+thiz.depth+')'\n"
					+ "            } else {\n"
					+ "                dict_with_thread_indentation_levels[current_threadid]=''\n"
					+ "                return ('TID '+current_threadid+': ').padEnd(14)+'('+thiz.depth+')'\n"
					+ "            } \n"
					+ "        }\n"
					+ "        function increase_indent() {\n"
					+ "            var current_threadid=Process.getCurrentThreadId()\n"
					+ "            if (current_threadid in dict_with_thread_indentation_levels) {\n"
					+ "                dict_with_thread_indentation_levels[current_threadid]=dict_with_thread_indentation_levels[current_threadid]+'  '\n"
					+ "            } else {\n"
					+ "                dict_with_thread_indentation_levels[current_threadid]=''\n"
					+ "            } \n"
					+ "        }\n"
					+ "        function decrease_indent() {\n"
					+ "            var current_threadid=Process.getCurrentThreadId()\n"
					+ "            if (current_threadid in dict_with_thread_indentation_levels) {\n"
					+ "                dict_with_thread_indentation_levels[current_threadid]=dict_with_thread_indentation_levels[current_threadid].slice(0,-2)\n"
					+ "            } else {  //we must never enter the else clause\n"
					+ "                dict_with_thread_indentation_levels[current_threadid]=''\n"
					+ "            } \n"
					+ "        }\n\n";
		}
		
		return retval;
	}
	
	protected String tid_and_indent_code()
	{
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isIncludeTIDAndIndentationcheckboxchecked)
		{
			return "tid_and_indent(this)+";
		}
		return "";
	}
	
	protected String increase_console_indent_if_chosen()
	{
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isIncludeTIDAndIndentationcheckboxchecked)
		{
			return "                        increase_indent()\n";
		}
		return "";
	}
	
	protected String decrease_console_indent_if_chosen()
	{
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isIncludeTIDAndIndentationcheckboxchecked)
		{
			return "                        decrease_indent()\n";
		}
		return "";
	}
	

	/*
	 * Careful: this does not walk the call graph, it enumerates the paths of it, because the path is what is printed as the
	 * reason of the hook. There is no set of already visited functions, so a function that is reached through ten different
	 * paths is expanded ten times, and the number of the paths is multiplied at every level of depth. On a densely
	 * connected or recursive call graph, and with the depth that the dialog allows, that grows very fast.
	 * The monitor is therefore consulted from inside the loop, and not only after a whole level has been built, so that the
	 * user can cancel while a level is being expanded and can see how many references have been gathered so far.
	 */
	protected ArrayList<ContainerForFunctionReferences> handle_outgoing_references_for_one_depth_level(ArrayList<ContainerForFunctionReferences> incoming_functions_from_previous_level,int current_depth)
	{
		int i;
		ArrayList<ContainerForFunctionReferences> retval=new ArrayList<ContainerForFunctionReferences>();
		for (i=0;i<incoming_functions_from_previous_level.size();i++)
		{
			if (i%100==0 && this.incoming_hook_generator.incoming_monitor!=null)
			{
				if (this.incoming_hook_generator.incoming_monitor.isCancelled()) {return retval;} //check for cancellation by the user
				this.incoming_hook_generator.incoming_monitor.setMessage("Outgoing calls, level "+current_depth+", "+i+"/"+incoming_functions_from_previous_level.size()+" of the previous level, "+retval.size()+" gathered...");
			}
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
					/*A single function can have a very large number of calls, so the monitor is consulted inside this loop as well*/
					if (retval.size()%20000==0 && this.incoming_hook_generator.incoming_monitor!=null)
					{
						if (this.incoming_hook_generator.incoming_monitor.isCancelled()) {return retval;} //check for cancellation by the user
						this.incoming_hook_generator.incoming_monitor.setMessage("Outgoing calls, level "+current_depth+", "+retval.size()+" gathered...");
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
	
	

	/*The same as the outgoing one above, and the monitor is consulted from inside the loops for the very same reason*/
	protected ArrayList<ContainerForFunctionReferences> handle_incoming_references_for_one_depth_level(ArrayList<ContainerForFunctionReferences> called_functions_from_previous_level,int current_depth)
	{
		int i;
		ArrayList<ContainerForFunctionReferences> retval=new ArrayList<ContainerForFunctionReferences>();
		for (i=0;i<called_functions_from_previous_level.size();i++)
		{
			if (i%100==0 && this.incoming_hook_generator.incoming_monitor!=null)
			{
				if (this.incoming_hook_generator.incoming_monitor.isCancelled()) {return retval;} //check for cancellation by the user
				this.incoming_hook_generator.incoming_monitor.setMessage("Incoming references, level "+current_depth+", "+i+"/"+called_functions_from_previous_level.size()+" of the previous level, "+retval.size()+" gathered...");
			}
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
					/*A single function can be called from a very large number of places, so the monitor is consulted inside this loop as well*/
					if (retval.size()%20000==0 && this.incoming_hook_generator.incoming_monitor!=null)
					{
						if (this.incoming_hook_generator.incoming_monitor.isCancelled()) {return retval;} //check for cancellation by the user
						this.incoming_hook_generator.incoming_monitor.setMessage("Incoming references, level "+current_depth+", "+retval.size()+" gathered...");
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
				//OLD_API:retval+=spaces+"current_function_start_address=Module.findBaseAddress(module_name_"+this.incoming_hook_generator.current_program_name_sanitized+").add(0x"+Long.toHexString(current_function.getEntryPoint().getOffset()-this.incoming_hook_generator.image_base.getOffset())+");\n";
				/*Careful: the offset is signed, so the absolute value is emitted and the sign is expressed by the add()/sub()*/
				long offset_of_function_start_from_the_image_base=current_function.getEntryPoint().getOffset()-this.incoming_hook_generator.image_base.getOffset();
				retval+=spaces+"current_function_start_address=Process.getModuleByName(module_name_"+this.incoming_hook_generator.current_program_name_sanitized+").base."+return_frida_operation_for_offset(offset_of_function_start_from_the_image_base)+"("+return_hex_str_for_absolute_value_of_offset(offset_of_function_start_from_the_image_base)+");\n";
				retval+=spaces+"dict_from_function_names_to_function_start_addresses[\""+current_function_name_sanitized+"\"]=current_function_start_address;\n";
				retval+=spaces+"dict_from_current_addresses_to_function_start_addresses["+current_addr_js_variable+"]=current_function_start_address;\n";
				retval+=spaces+"dict_from_function_start_addresses_to_function_names[current_function_start_address]=\""+current_function_name_sanitized+"\";\n";
			}
		}
		return retval;
	}
	
	
	String populate_data_structure_that_holds_Interceptor_attach_objects(String current_addr_js_variable)
	{
		String retval="";
		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isCreateDataStructureWithInterceptorAttachObjectscheckboxchecked)
		{
			retval+="dict_with_objects_returned_from_attach["+current_addr_js_variable+"]=";
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
		/*Careful: the comparisons below must be done with equals(). DataType.toString() is not guaranteed to return an interned string, and if these checks silently fail, floating point parameters end up being described to frida as integers of the same size*/
		else if (param_datatype.toString().equals("double"))
		{
			str_for_param+="'double'";
		}
		else if (param_datatype.toString().equals("float"))
		{
			str_for_param+="'float'";
		}
		else if (param_datatype.toString().equals("int"))
		{
			str_for_param+="'int'";
		}
		else if (param_datatype.toString().equals("long"))
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
			hook_str=hook_str.concat("        //Current function has variadic number of arguments, interceptor.replace not supported yet\n");
			return hook_str;
		}
		if (current_function.getReturnType()==null)
		{
			hook_str=hook_str.concat("        //Current function has undefined type of return value\n");
			return hook_str;
		}
		
		int size_of_returntype=current_function.getReturnType().getLength();
		//void is not ZeroLength, but getLength returns 0
		if (current_function.getReturnType().isZeroLength() || (!current_function.getReturnType().toString().equals("void") && size_of_returntype!=1 && size_of_returntype!=2 && size_of_returntype!=4 && size_of_returntype!=8)  )
		{
			/*The name of the type comes from the database, which took it from the analysed file, so it cannot be written into a comment as it is*/
			hook_str=hook_str.concat("        //Current function has an unaccepted return type:"+return_text_safe_for_a_javascript_comment(current_function.getReturnType().toString())+"\n");
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
	
	
	
	protected String return_sanitized_name_of_parameter_for_function_at_position(Function incoming_function, int i)
	{
		String retval="";
		int num_of_params=incoming_function.getParameterCount();
		Parameter param;
		if (i>=0 && i<num_of_params)
		{
			param=incoming_function.getParameter(i);
		}
		else
		{
			retval= "invalid_param";
			return retval;
		}
		String sanitized_param_name=param.getName().replaceAll("[^"+characters_allowed_in_variable_name+"]", "_");
		retval=sanitized_param_name;
		return retval;
	}
	
	
	
	protected Boolean do_sanitized_function_argument_names_result_in_name_conflicts(Function incoming_function)
	{
		boolean retval=false;
		int num_of_params=incoming_function.getParameterCount();
		ArrayList<String> sanitized_param_names= new ArrayList<String>();
		for (int i=0;i<num_of_params;i++)
		{
			String new_param_name=return_sanitized_name_of_parameter_for_function_at_position(incoming_function,i);
			if (sanitized_param_names.contains(new_param_name))
			{
				return true;
			}
			sanitized_param_names.add(new_param_name);
		}
		return retval;
	}
	
	

	
	/* This function tries to predict, whether there might be a future reason for hooking the current address, for which special treatment (code that may later be needed to be added) is required.
	 * For example, if the current address is about a dynamic call instruction, then maybe, a later hook for the same address is asked to print the where the code will go.
	 * As the hook string is generated only once, that string will have to put a placeholder for the code that does the "special treatment". 
	 * This function only checks whether there is any chance that the current instruction may need a "special treatment" by iterating over all the implemented reasons for "special treatment", and checking if they may apply.
	 */
	protected Boolean can_there_be_any_reason_why_this_address_may_need_code_that_is_later_added_in_the_hook(Address addr)
	{
		/*
		 * This decides whether a placeholder is put inside the hook. Whether the address is then registered for
		 * backpatching is NOT decided by asking this function again: update_internal_data_structures() looks at the hook
		 * that was actually generated and registers the address only if a placeholder really ended up inside it. That is
		 * the only way for the two to be unable to disagree, because a hook can be generated through several paths (a
		 * function hook without an onEnter(), a thunk or an external function that is only commented out, an address
		 * that is not an instruction) and in some of them no placeholder is emitted at all.
		 */
		Instruction current_instruction=this.incoming_hook_generator.current_program_listing.getInstructionAt(addr);
		return does_the_current_instruction_definitely_need_hook_code_to_also_be_added_later(current_instruction);
	}
	
	/*
	 * The architecture of the program, asked once and in one place each.
	 *
	 * Careful: these three are what keeps the two decisions about the computed calls in step. The pass that replaces the
	 * placeholders is only run at all when the first of the two says that some hook of the batch might need it, and the
	 * placeholders themselves are written when the second one says that a particular instruction needs it. Those two used to
	 * carry a list of architectures each, and the day one list gained an architecture that the other did not, the placeholders
	 * went into the hooks and the pass that replaces them never ran, so their text was left inside the generated script. With
	 * the strings written once there is nothing left to fall out of step.
	 *
	 * Careful as well: an architecture belongs here only when ComputedCallHookGenerator really chooses a parser for it.
	 */
	protected Boolean the_program_is_x86()
	{
		return Boolean.valueOf(this.incoming_hook_generator.current_program_language.getLanguageID().toString().indexOf("x86:LE:")>=0);
	}

	protected Boolean the_program_is_aarch64()
	{
		return Boolean.valueOf(this.incoming_hook_generator.current_program_language.getLanguageID().toString().indexOf("AARCH64:LE:64")>=0);
	}

	protected Boolean the_program_is_arm32()
	{
		return Boolean.valueOf(this.incoming_hook_generator.current_program_language.getLanguageID().toString().indexOf("ARM:LE:32")>=0);
	}

	protected Boolean does_the_architecture_of_the_program_have_a_parser_of_computed_calls()
	{
		return Boolean.valueOf(the_program_is_x86().booleanValue() || the_program_is_aarch64().booleanValue()
				|| the_program_is_arm32().booleanValue());
	}

	/*
	 * Used for efficiency, in order to avoid an entire pass over the generated hooks when no hook could possibly need it.
	 */
	protected Boolean is_there_a_chance_that_some_hooks_generated_in_the_current_batch_require_code_that_is_later_added_in_the_hook()
	{
		if (this.incoming_hook_generator.isAdvanced && does_the_architecture_of_the_program_have_a_parser_of_computed_calls().booleanValue() &&
				(this.incoming_hook_generator.advancedhookoptionsdialog.isOutDynamicCallReferencesfromAddressCheckBoxchecked || this.incoming_hook_generator.advancedhookoptionsdialog.isOutDynamicCallReferencesfromFunctionCheckBoxchecked))
		{
			return true;
		}
		return false;
	}
		
	/*
	 * This is the single place where it is decided whether an instruction is a computed call/jump whose destination we
	 * can report. It used to also require that the reason of the hook contains a specific sentence, which made it
	 * disagree with can_there_be_any_reason_why_this_address_may_need_code_that_is_later_added_in_the_hook() whenever
	 * the same address had already been hooked for a different reason. The mnemonics listed here must be exactly the
	 * ones that the corresponding ParserOfComputedCalls can translate.
	 */
	protected Boolean does_the_current_instruction_definitely_need_hook_code_to_also_be_added_later(Instruction current_instruction)
	{
		if (this.incoming_hook_generator.isAdvanced && current_instruction!=null && current_instruction.getFlowType().isComputed())// && current_instruction.getFlowType().isCall()) //Uncomment to restrict selection to computed hooks
		{
			if (this.incoming_hook_generator.advancedhookoptionsdialog.isOutDynamicCallReferencesfromAddressCheckBoxchecked || this.incoming_hook_generator.advancedhookoptionsdialog.isOutDynamicCallReferencesfromFunctionCheckBoxchecked)
			{
				String current_instruction_mnemonic=current_instruction.getMnemonicString().toLowerCase().trim();

				/*
				 * Both widths of x86, and not only the 64 bit one: the parser knows the 32 bit registers as well, and a 32 bit
				 * program used to be refused here and nowhere else, so the two options about the computed calls quietly produced
				 * nothing at all for it, with no comment to say why.
				 */
				if (the_program_is_x86().booleanValue() &&
						(current_instruction_mnemonic.equals("call") || current_instruction_mnemonic.equals("jmp"))
					)

				{
					return true;
				}

				/*Careful: bx is an ARM32 mnemonic and it does not exist in AArch64. These are all the branches to a register, including the ones that authenticate the destination*/
				if (the_program_is_aarch64().booleanValue() &&
						(current_instruction_mnemonic.equals("blr") || current_instruction_mnemonic.equals("br") ||
						 current_instruction_mnemonic.equals("blraa") || current_instruction_mnemonic.equals("blrab") ||
						 current_instruction_mnemonic.equals("blraaz") || current_instruction_mnemonic.equals("blrabz") ||
						 current_instruction_mnemonic.equals("braa") || current_instruction_mnemonic.equals("brab") ||
						 current_instruction_mnemonic.equals("braaz") || current_instruction_mnemonic.equals("brabz") )
					)
				{
					return true;
				}

				/*
				 * ARM (32 bit) and Thumb. The mnemonics can carry a condition suffix (bxeq) and the wide/narrow suffix
				 * of Thumb (ldr.w), so they are matched by their beginning. A mov or a ldr only reaches this point when
				 * it writes to the program counter, because the flow of the instruction has already been checked to be a
				 * computed one. If the ARM32 parser cannot translate a specific form, a comment is emitted in the place
				 * of the code, so accepting a bit more here than what can be translated is harmless.
				 */
				if (the_program_is_arm32().booleanValue() &&
						(current_instruction_mnemonic.startsWith("bx") || current_instruction_mnemonic.startsWith("blx") ||
						 current_instruction_mnemonic.startsWith("mov") || current_instruction_mnemonic.startsWith("ldr") )
					)
				{
					return true;
				}
			}
		}
		return false;
	}


	/*
	 * Returns where inside the generated hook the code for the address will be injected. The value is stored in the
	 * internal data structures and it is read back when the hooks are backpatched, in order to pick the indentation and
	 * in order to know whether the registers of the hooked thread can be read at that point.
	 */
	protected String return_type_of_hook_that_will_contain_the_address(Address addr)
	{
		Function function_containing_addr=this.incoming_hook_generator.current_program_listing.getFunctionContaining(addr);
		Boolean we_are_at_start_of_function=(function_containing_addr!=null && function_containing_addr.getEntryPoint().equals(addr));

		if (this.incoming_hook_generator.isAdvanced && this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateNormalAddressHooksForFunctionBeginningscheckboxchecked)
		{
			we_are_at_start_of_function=false; //the user asked for the function beginnings to be treated as any other address
		}
		if (!we_are_at_start_of_function.booleanValue())
		{
			return "simple instruction";
		}
		if (!this.incoming_hook_generator.use_interceptor_attach_instead_of_replace_in_function_hooks &&
				identify_errors_if_interceptor_replace_is_used(function_containing_addr,function_containing_addr.getParameterCount()).equals(""))
		{
			/*The hook of this function will be an Interceptor.replace() with a NativeCallback, which is an arrow function and therefore has no InvocationContext*/
			return "start of function with interceptor replace";
		}
		/*
		 * What is left is a hook with an onEnter(), which is where the code goes. Careful: when the user asks for function
		 * hooks without an onEnter() there is nowhere to put the code, but this function is never reached in that case,
		 * because no placeholder is emitted and therefore the address is never registered for backpatching.
		 */
		return "start of function";
	}


	/*Returns the address in a form that can be used inside a javascript identifier. Careful: Address.toString() contains the name of the address space, followed by a colon, for every address space other than the default one*/
	/*
	 * Turns any piece of text into something that javascript accepts as a part of a name, by replacing every character that is
	 * not allowed with an underscore.
	 *
	 * Careful: the result is only a part of a name and never a whole one. Everything that is built with it carries a prefix of
	 * its own, offset_of_ or module_name_ or dynamic_address_of_ , which is what keeps a name that begins with a digit, or one
	 * that is empty, from being written into the script.
	 */
	public static String return_sanitized_string_for_a_variable_name(String in_str)
	{
		if (in_str==null)
		{
			return "";
		}
		return in_str.replaceAll("[^"+characters_allowed_in_variable_name+"]", "_");
	}

	/*
	 * The same, for an address. Careful: Address.toString() puts the name of the address space and a colon in front of every
	 * address that is not in the default space, so an address of an overlay arrives here as something like MYOVERLAY::00001000
	 * and the colons are what would otherwise end up inside a name.
	 */
	protected String return_sanitized_address_str_for_variable_name(Address addr)
	{
		return return_sanitized_string_for_a_variable_name(addr.toString());
	}


	/*
	 * An address is not always above the image base of the program, as a memory block can be mapped below it, so the offset
	 * from the image base is a signed number.
	 * Careful: such an offset must never be handed to Long.toHexString() as it is, because a negative number comes out as a
	 * huge unsigned value (-0x1000 becomes fffffffffffff000) and the generated code would then point very far away from
	 * where it should. These two functions are the only place where that is decided: the hexadecimal is always the absolute
	 * value of the offset, and its sign is expressed by the operation that is applied on the base of the module.
	 * They are public and static so that the parsers of the computed calls, which live in another package, use them as well.
	 *
	 * Careful: a negative offset is handled here, but there is a case that is NOT handled at all, and that these functions
	 * cannot even detect on their own. An address that belongs to an overlay, or to an address space other than the default
	 * one, does not correspond to "the base of the module plus an offset" in the first place, whatever the sign of that
	 * offset is. The code that is generated for such an address is arithmetically consistent but points nowhere useful, and
	 * the honest thing to emit for it would be a comment instead of a hook. Detecting it means looking at the address space
	 * of the address, and at whether it falls inside the image of the program, at the places that generate the hooks.
	 */
	public static String return_hex_str_for_absolute_value_of_offset(long offset_from_the_image_base)
	{
		if (offset_from_the_image_base<0)
		{
			return "0x"+Long.toHexString(-offset_from_the_image_base);
		}
		return "0x"+Long.toHexString(offset_from_the_image_base);
	}

	public static String return_frida_operation_for_offset(long offset_from_the_image_base)
	{
		if (offset_from_the_image_base<0)
		{
			return "sub";
		}
		return "add";
	}
	
	
	protected void update_internal_data_structures(Address addr,String hook_str, String reason_for_hook_generation)
	{
		this.incoming_hook_generator.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch++;
		String tmpstr=String.valueOf(this.incoming_hook_generator.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch)+"|"+reason_for_hook_generation;
		this.incoming_hook_generator.internal_structures_for_hook_generation.Addresses_for_current_hook_str.put(addr.toString(),tmpstr); //this is the initial placement of this address in the Addresses_for_current_hook_str data structure
		this.incoming_hook_generator.internal_structures_for_hook_generation.addresses_for_which_hook_is_generated_in_order_of_appearance.add(addr);
		this.incoming_hook_generator.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.add(hook_str);
		/*
		 * If the hook that was just generated really contains a placeholder, then register the address, so that the
		 * placeholder is replaced when the hooks are backpatched.
		 * Careful: the check has to be made on the hook itself and not by asking again whether this address should have
		 * a placeholder. Not every path that generates a hook emits one: a function hook that has no onEnter() has
		 * nowhere to put it, and a thunk, an external function or an address which is not an instruction only produce a
		 * comment in the place of the hook. If the address were registered in those cases, the code that is generated for
		 * it during the backpatching would replace nothing and would be silently thrown away.
		 */
		if (this.incoming_hook_generator.isAdvanced && hook_str.indexOf(prefix_of_placeholder_for_hook_code_to_be_added_later+addr)>=0)
		{
			HashMap<String,String> tmphm= new HashMap<String,String>();
			/*Careful: the addresses have to be compared with equals() (this is done inside the function below). The Address that is held by the Function is a different object than the one we are iterating with, even when both describe the same address*/
			String reason_for_computed_call_or_jump=return_type_of_hook_that_will_contain_the_address(addr);
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
	

	/*
	 * Makes a piece of text safe to put inside a string literal of the generated javascript, whichever of the two kinds of
	 * quote the literal is written with.
	 *
	 * Careful: both quote characters are escaped and not only the double one. Escaping a single quote inside a literal that is
	 * written with double quotes is harmless, javascript reads \' as ' , whereas leaving it alone means that whoever writes the
	 * next literal with single quotes has to remember to use a different escaper. The name of the program is exactly such a
	 * piece of text: it is put inside single quotes, it comes from the project and a user can call a program anything at all.
	 */
	public static String return_string_escaped_for_a_javascript_string_literal(String in_str)
	{
		if (in_str==null)
		{
			return "";
		}
		StringBuffer retval=new StringBuffer(in_str.length()+16);
		for (int i=0;i<in_str.length();i++)
		{
			char current_char=in_str.charAt(i);
			if (current_char=='\'') { retval.append("\\'"); }
			else if (current_char=='\"') { retval.append("\\\""); }
			else if (current_char=='\\') { retval.append("\\\\"); }
			else if (current_char=='\n') { retval.append("\\n"); }
			else if (current_char=='\r') { retval.append("\\r"); }
			else if (current_char=='\t') { retval.append("\\t"); }
			/*
			 * Careful: the line separator and the paragraph separator end a line of javascript exactly as a line feed does, and they
			 * are not control characters, so the test below for those does not reach them. A string literal of a modern runtime does
			 * accept them as they are, but writing them out costs nothing and keeps this function safe to reuse.
			 */
			else if (current_char==0x2028 || current_char==0x2029) { retval.append(String.format("\\u%04x",(int)current_char)); }
			else if (current_char<0x20 || current_char==0x7f) { retval.append(String.format("\\u%04x",(int)current_char)); }
			else { retval.append(current_char); }
		}
		return retval.toString();
	}

	/*
	 * Makes a piece of text safe to put inside a comment of the generated javascript.
	 *
	 * Careful: javascript ends a line at four characters and not at two. A line feed and a carriage return do it, and so do the
	 * line separator and the paragraph separator, which are not control characters and survive a test that only looks for those.
	 * Any one of them inside a comment that begins with // ends that comment where it sits and leaves the rest of the sentence
	 * behind as code, which is how a name inside an analysed binary becomes a statement of a generated script.
	 *
	 * All four become spaces. The end of a block comment is broken apart as well, so that this can be trusted for a comment
	 * written the other way too. The text of a comment is only ever read by a person, so a space in the place of something that
	 * could not be printed anyway costs nothing.
	 *
	 * This is the counterpart of return_string_escaped_for_a_javascript_string_literal(). Text that goes into a literal needs that
	 * one, text that goes into a comment needs this one, and nothing from a database may be written into either without passing
	 * through whichever of the two fits where it lands.
	 */
	public static String return_text_safe_for_a_javascript_comment(String in_str)
	{
		if (in_str==null)
		{
			return "";
		}
		StringBuffer retval=new StringBuffer(in_str.length()+16);
		for (int i=0;i<in_str.length();i++)
		{
			char current_char=in_str.charAt(i);
			if (current_char=='\n' || current_char=='\r' || current_char==0x2028 || current_char==0x2029)
			{
				retval.append(' ');
			}
			else if (current_char=='*' && i+1<in_str.length() && in_str.charAt(i+1)=='/')
			{
				retval.append("* ");	//the end of a block comment, taken apart so that it cannot close one
			}
			else
			{
				retval.append(current_char);
			}
		}
		return retval.toString();
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
		/*Careful: the result of this is substituted inside a console.log("...") of the generated script, so it has to be escaped. The reasons carry text that the user has typed, such as the regular expressions of the function names, and a regular expression is full of backslashes*/
		return return_string_escaped_for_a_javascript_string_literal(retval);
	}
	
	protected String generate_random_string_from_pool(String pool,int length)
	{
		String retval="";
		Random random=new Random();
		for (int i=0;i<length;i++)
		{
			int select = random.nextInt(pool.length());
			retval+=pool.charAt(select);
		}
		return retval;
	}
	
	
	/*
	 * The name of a register to show in the hints that suggest how a register can be changed.
	 * Careful: the hint used to name x0 whatever the program was, which is a register that an x86 target does not have at all.
	 * A processor that is not one of the ones below gets a placeholder instead of a name. The line sits inside a comment, so a
	 * placeholder costs nothing and reads as what it is, whereas any name picked at random would be a name of a register that
	 * the reader then has to check.
	 */
	protected String return_the_name_of_a_register_for_the_hints()
	{
		String identifier_of_the_language="";
		if (this.incoming_hook_generator!=null && this.incoming_hook_generator.current_program_language!=null)
		{
			identifier_of_the_language=this.incoming_hook_generator.current_program_language.getLanguageID().toString();
		}
		if (identifier_of_the_language.indexOf("AARCH64")>=0) { return "x0"; }
		if (identifier_of_the_language.indexOf("ARM")>=0) { return "r0"; }
		if (identifier_of_the_language.indexOf("x86")>=0 && identifier_of_the_language.indexOf(":64:")>=0) { return "rax"; }
		if (identifier_of_the_language.indexOf("x86")>=0) { return "eax"; }
		if (identifier_of_the_language.indexOf("MIPS")>=0) { return "a0"; }
		if (identifier_of_the_language.indexOf("PowerPC")>=0) { return "r3"; }
		return "<name of the register>";
	}

	/*
	 * The hint that shows how a register is changed, for a hook that runs before the real code does.
	 * Both halves of what it says are worth saying: the registers can be read there, and a value written into them is really
	 * used, because frida keeps the context in memory while the hook runs and puts it back into the machine before it lets the
	 * hooked code continue.
	 */
	protected String return_the_hint_that_shows_how_a_register_is_changed(String spaces)
	{
		return spaces+"// this.context."+return_the_name_of_a_register_for_the_hints()+"=0x1;"
				+"   //any register of the context can be read here, and a value written into one of them is put back before the hooked code continues\n";
	}

	/*
	 * The same hint for the inside of an Interceptor.replace().
	 * There the second half is not true, and saying nothing about it is what makes somebody write the line and wonder why it
	 * does nothing: the callback does not run before the function, it takes the place of the function, so nothing ever puts the
	 * context back into the machine. Reading it is still useful, for a register that the prototype of the function does not
	 * carry, and the two things that do change what happens are named here instead.
	 */
	protected String return_the_hint_that_says_that_writing_a_register_does_nothing(String spaces)
	{
		return spaces+"//Careful: reading is fine, writing is not. \"this.context."+return_the_name_of_a_register_for_the_hints()+"=0x1;\" would be ignored here,\n"
			  +spaces+"//because this callback takes the place of the function instead of running before it, so nothing puts the context back into the\n"
			  +spaces+"//machine. To change what the function does with its arguments, pass other values to the original below, and to change what\n"
			  +spaces+"//the caller receives, return something else.\n";
	}

	protected String generate_import_hook_str_for_function(String raw_function_name, String properly_sanitized_function_name, int parameter_count,String sanitized_export_module_name, String varstr_for_resolver_and_matches,String spaces)
	{
		String retval="";
		String sanitized_fun_name=properly_sanitized_function_name;
		/*
		 * The two names go into a string literal of the generated script without being escaped, and that is safe because of what
		 * the caller does rather than because of anything here.
		 *
		 * Careful: the name of the function reaches this point only when every one of its characters is one of 0-9 a-z A-Z _ : @
		 * ~ ? $ . The caller does not repair a name that has anything else in it, it skips the import altogether and writes a
		 * comment saying so, and the name of the module is either the single character * or a name made of 0-9 a-z A-Z _ and the
		 * dot. So neither of them can carry a quote, a backslash or a character that cannot be typed.
		 *
		 * Whoever loosens either of those two filters has to escape here, with
		 * return_string_escaped_for_a_javascript_string_literal(), or this literal ends at the first quote of a name.
		 */
		retval+=spaces+"matches_"+varstr_for_resolver_and_matches+"=resolver_"+varstr_for_resolver_and_matches+".enumerateMatches('exports:"+sanitized_export_module_name+"!"+raw_function_name+"/i');\n";
		retval+=spaces+"if (matches_"+varstr_for_resolver_and_matches+".length>0)\n";
		retval+=spaces+"{\n";
		retval+=spaces+"    var first_match=matches_"+varstr_for_resolver_and_matches+"[0];\n";
		retval+=spaces+"    var dynamic_address_of_import_"+sanitized_fun_name+"=first_match.address;\n";
		/*The indentation follows the same shape as the rest of the interceptor hooks: the properties of the object are 12 columns deeper than the Interceptor.attach() that opens it, their bodies 4 more, and the closing brace lines up with the opening call*/
		retval+=spaces+"    Interceptor.attach(dynamic_address_of_import_"+sanitized_fun_name+", {\n"
			   +spaces+"                onEnter: function(args) {\n"
			   +spaces+"                    console.log(\"Entered import_"+sanitized_fun_name+"\");\n";
		if (parameter_count>=1)
		{
			retval+=spaces+"                    console.log('";
			for (int i=0;i<parameter_count;i++)
			{
				retval+="args["+i+"]='+args["+i+"]";
				if (i<parameter_count-1) { retval+="+' , "; }
				else { retval+=");\n"; }
			}
		}
		retval+=return_the_hint_that_shows_how_a_register_is_changed(spaces+"                    ")
			  +spaces+ "                },\n"
			  +spaces+ "                onLeave: function(retval) {\n"
			  +spaces+ "                    console.log(\"Exited import_"+sanitized_fun_name+", retval:\"+retval);\n"
			  +spaces+ "                    // retval.replace(0x1);\n"
			  +spaces+ "                }\n"
			  +spaces+ "    }); \n";
		retval+=spaces+"}\n";
		return retval;
	}
	
	boolean is_symbol_name_mangled_name(String symbol_name)
	{
		//Mangled Symbol. TODO: Provide a better check if a symbol is in a mangled form
		if (symbol_name.startsWith("_Z") || symbol_name.startsWith("?"))
		{
			return true;
		}
		return false;
	}

	String return_mangled_name_for_specific_address(Program incoming_program,Address incoming_address, Pattern pattern_to_match)
	{
		SymbolTable incoming_symbol_table=incoming_program.getSymbolTable();
		SymbolIterator symbol_interator=incoming_symbol_table.getSymbolsAsIterator(incoming_address);
		while(symbol_interator!=null && symbol_interator.hasNext())
		{
			Symbol next_symbol=symbol_interator.next();
			String symbol_name=next_symbol.getName();
			if (is_symbol_name_mangled_name(symbol_name))
			{
				
				if (pattern_to_match.matcher(symbol_name).matches())
				{
					return symbol_name;
				}
			}
		}
		return "";
	}
	
	/*
	 * The module that the resolver is told to look inside, worked out from the full name of an external symbol.
	 * A name of the shape KERNEL32.dll::GetLastError gives kernel32.dll , and anything else gives the single character * , which
	 * the caller turns into a search through every module. The name is only used when it is made of characters that are safe
	 * both for the query and for the string literal that the query is written into, and it is refused rather than repaired when
	 * it is not, which is what keeps the caller from having to escape anything.
	 */
	public static String return_sanitized_module_name_regex_for_dll_external_function_import(String full_symbol_name)
	{
		String retval="*"; //match any module
		if (full_symbol_name==null || !full_symbol_name.toLowerCase().contains(".dll::"))
		{
			return retval;
		}
		String[] split_values=full_symbol_name.toLowerCase().split("\\.dll\\:\\:",0);
		String dll_name=split_values[0];
		String sanitized_dll_name_with_dot=dll_name.toLowerCase().replaceAll("[^"+characters_allowed_in_variable_name+"\\."+"]", "_");
		if (!sanitized_dll_name_with_dot.equals(dll_name.toLowerCase()))
		{
			return retval;
		}
		retval=sanitized_dll_name_with_dot+".dll";
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
			String current_hook_for_addr=this.incoming_hook_generator.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.get(i);
			String hook_to_replace_later_code_placeholder="";

			/*Careful: the lookup in the hashmap has to be the first check of the two, as it is the cheap one. Asking the listing for the instruction of every single address of the batch would be a lot of work for nothing*/
			Instruction newinstr=null;
			if (this.incoming_hook_generator.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.containsKey(newaddr))
			{
				newinstr=this.incoming_hook_generator.current_program_listing.getInstructionAt(newaddr);
			}
			//newinstr is expected to not be null for a registered address, as a hook is supposed to be generated for it, but it is checked anyway so that a disassembly that changed under our feet cannot bring the task down
			if (newinstr!=null)
			{
				for (String reason: this.incoming_hook_generator.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.get(newaddr).keySet())
				{
					if (reason.equals("Computed Call/Jump"))
					{
						String options_for_computed_call_or_jump = this.incoming_hook_generator.internal_structures_for_hook_generation.Addresses_that_need_hook_code_to_be_added_at_a_later_stage.get(newaddr).get(reason);
						String spaces="";
						/*
						 * The registers are available at every point where this code can be injected: the body of the standalone
						 * callback of a simple address hook, the onEnter() of a function hook, and the NativeCallback of an
						 * Interceptor.replace(), which is emitted as a normal function so that frida can bind the invocation
						 * context to it. Careful: if that NativeCallback ever becomes an arrow function again, this has to
						 * become false for the interceptor replace case, as an arrow function keeps the "this" of the scope
						 * that encloses it.
						 */
						Boolean register_context_is_available=true;
						if (options_for_computed_call_or_jump.equals("simple instruction"))
						{
							//the code is injected in the body of the function_to_call_when_code_reaches_<addr>() of the hook
							spaces="            ";
						}
						else
						{
							//the code is injected in the body of the onEnter() (or of the NativeCallback) of the hook of a function
							spaces="                        ";
						}

						/*Careful: an instruction is not guaranteed to have an operand, so the result of the split has to be checked before it is indexed*/
						String arg_of_call="";
						String[] mnemonic_and_arg_of_instruction=newinstr.toString().split(" ",2);  //remove of CALL/BLR... and get the rest, the argument
						if (mnemonic_and_arg_of_instruction.length>1)
						{
							arg_of_call=mnemonic_and_arg_of_instruction[1].toLowerCase().trim();
						}
						String mnemonic_of_command=newinstr.getMnemonicString().toLowerCase().trim();
						/*What is passed is the name of the javascript variable that holds the name of the module. The generated code resolves the module through it, on its own, so that it stays self contained*/
						ComputedCallHookGenerator hookgenerator=new ComputedCallHookGenerator(this.incoming_hook_generator,this.incoming_hook_generator.current_program,newaddr,newinstr,mnemonic_of_command,arg_of_call,"module_name_"+this.incoming_hook_generator.current_program_name_sanitized);
						hook_to_replace_later_code_placeholder=hook_to_replace_later_code_placeholder.concat(hookgenerator.provide_hook_code(spaces,register_context_is_available));
					}
					//Other possible reasons can go here
				}
			}

			/*
			 * Careful: the replacement has to happen for every hook, and not only for the ones that are registered as
			 * needing more code. If a placeholder was inserted into a hook that is not registered here, then leaving it
			 * alone would let the text of the placeholder itself end up inside the generated script. For the hooks that
			 * are not registered, hook_to_replace_later_code_placeholder is the empty string, so the placeholder is
			 * simply removed.
			 */
			this.incoming_hook_generator.internal_structures_for_hook_generation.hooks_generated_per_address_in_order_of_appearance.set(i,current_hook_for_addr.replace(prefix_of_placeholder_for_hook_code_to_be_added_later+newaddr,hook_to_replace_later_code_placeholder));

			if (i%100==0 && this.incoming_hook_generator.incoming_monitor.isCancelled()) {return ;} //check for cancellation by the user
			if (i%1000==0) {this.incoming_hook_generator.incoming_monitor.setMessage("Backpatching hooks that need more code "+(int)((i*100)/this.incoming_hook_generator.internal_structures_for_hook_generation.how_many_addresses_have_been_hooked_so_far_in_this_batch)+"%...");}
		}
				
	}
	
	
	
	

	
	/*
	 * The javascript that asks frida for a backtrace.
	 *
	 * Two things used to be decided by one single flag here, and they are not the same thing at all:
	 *
	 *  - whether this hook is at the beginning of a function, which is what the first two entries of the combo box are
	 *    about ("at function beginnings"), and
	 *  - whether the context of the hooked thread can be reached from the place where this line is written.
	 *
	 * The second one is true in every hook that this plugin generates: the body of an address hook is a normal named
	 * function that Interceptor.attach() calls, the onEnter of a function hook is a normal function, and the NativeCallback
	 * of an Interceptor.replace() is emitted as a normal function as well. Frida binds the "this" of all three to the
	 * invocation context, so this.context is there in all of them.
	 * The indentation is the third thing that used to be decided by that same flag, and it belongs to the caller, which is
	 * the only one that knows how deep the block it is writing into is.
	 */
	protected String generate_backtrace_for_hook(Boolean the_hook_is_at_the_beginning_of_a_function,String indentation)
	{
		String hook_str="";
		String bt="";
		/*
		 * Careful: never pass null here. Thread.backtrace(null,...) does not unwind from the hooked place, it unwinds from
		 * wherever the javascript of the hook happens to be running, so the first frames of the result are frida's own and
		 * the caller that the user is looking for may not be in the list at all.
		 */
		String ctx="this.context";
		String spaces=indentation;
		
		if (!this.incoming_hook_generator.isAdvanced || !this.incoming_hook_generator.advancedhookoptionsdialog.isGenerateBacktraceCheckboxchecked)
		{
			return "";
		}
		if ((this.incoming_hook_generator.advancedhookoptionsdialog.GenerateBacktracecomboBox.getSelectedIndex()==0 
				|| this.incoming_hook_generator.advancedhookoptionsdialog.GenerateBacktracecomboBox.getSelectedIndex()==1)
				&& !the_hook_is_at_the_beginning_of_a_function.booleanValue())
		{
			return "";
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
		
		hook_str=hook_str.concat(spaces+"console.log("+this.tid_and_indent_code()+"\"Backtrace:\"+");
		hook_str=hook_str.concat("Thread.backtrace("+ctx+", "+bt+")"
								+ ".map(DebugSymbol.fromAddress).join('\\n'+"+this.tid_and_indent_code()+"'') + '\\n');\n");
		return hook_str;
	}
	
	
	
	
	
}
