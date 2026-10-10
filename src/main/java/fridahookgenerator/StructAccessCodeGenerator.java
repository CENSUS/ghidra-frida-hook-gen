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

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.HashMap;

import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;

/*
 * This class generates code for struct fields, to make their access easier from javascript.
 */

public class StructAccessCodeGenerator {

	private PluginTool incoming_plugintool;
	protected Program current_program;
	private ConsoleService consoleService;
	Structure incoming_structure;
	private String characters_allowed_in_variable_name="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
	Boolean is_recursive_call;
	HashMap <String,String> included_structures;
	Boolean is_invoked_programmatically_from_the_api;
	Boolean should_output;
	String[] list_of_paths_to_be_excluded;
	
	public StructAccessCodeGenerator(PluginTool incoming_plugintool, Program current_program, Structure incoming_structure, 
			String[] list_of_paths_to_be_excluded,Boolean is_recursive_call , Boolean is_invoked_programmatically , Boolean should_output ) {
		
		this.incoming_plugintool=incoming_plugintool;
		this.current_program=current_program;
		this.incoming_structure=incoming_structure;
		this.is_recursive_call=is_recursive_call;
		this.included_structures=new HashMap<String,String>();
		this.is_invoked_programmatically_from_the_api=is_invoked_programmatically;
		this.should_output=should_output;		
		this.consoleService=incoming_plugintool.getService(ConsoleService.class); 
		this.list_of_paths_to_be_excluded=new String[list_of_paths_to_be_excluded.length];
		for (int i=0;i<list_of_paths_to_be_excluded.length;i++)
		{
			this.list_of_paths_to_be_excluded[i]=list_of_paths_to_be_excluded[i];
			this.included_structures.put(list_of_paths_to_be_excluded[i], "already_included");
		}
	}
	
	
	protected Boolean is_structure_empty(Structure in_struct)
	{
		if (in_struct.getNumComponents()==0 || in_struct.isZeroLength())
		{
			return true;
		}
		return false;
	}


	/*
	 * Careful: the excluded paths are also placed inside the included_structures, so that no class is generated for them.
	 * That is why the exclusion has to be checked against the list itself and not against the included_structures, whose
	 * other entries are structures for which a class *has* been generated.
	 */
	protected Boolean is_structure_path_excluded(String path_of_structure)
	{
		if (path_of_structure==null)
		{
			return false;
		}
		for (int i=0;i<this.list_of_paths_to_be_excluded.length;i++)
		{
			if (path_of_structure.equals(this.list_of_paths_to_be_excluded[i]))
			{
				return true;
			}
		}
		return false;
	}
	
	
	protected String generate_recursive_hook_str(Structure in_struct)
	{
		String hook_str="";
		DataTypeComponent[] components = in_struct.getComponents(); //all components, even filler fields
		
		//generate recursive hooks for subcomponents
		for (int i=0;i<components.length;i++)
		{
			if (components[i].getDataType() instanceof Structure && !this.included_structures.containsKey(components[i].getDataType().getPathName())) 
			{
				String this_hook=generate_recursive_hook_str((Structure) components[i].getDataType());
				hook_str+=this_hook;
				this.included_structures.put(components[i].getDataType().getPathName(), this_hook);
			}
		}
		
		//now generate proper hook for ourselves
		if (!this.included_structures.containsKey(in_struct.getPathName()))
		{
			hook_str+=generate_hook_str_for_one_struct(in_struct,true);
		}
		
		return hook_str;
		
	}
	
	
	public String generate_hook_str()
	{
		String hook_str="";
		
		if (!this.is_recursive_call)
		{
			hook_str+=generate_hook_str_for_one_struct(this.incoming_structure,false); 
		}
		else
		{
			hook_str+=generate_recursive_hook_str(this.incoming_structure); 
		}
		
		if (this.should_output)
		{
			handle_output(hook_str);
		}
		
		return hook_str;
		
	}

	protected String generate_hook_str_for_one_struct(Structure dt_as_structure, Boolean initialize_subcomponent_members)
	{
		
		String hook_str="";
		
		
		String name_of_struct=dt_as_structure.getPathName().replaceAll("[^"+this.characters_allowed_in_variable_name+"]", "_");
		
		DataTypeComponent[] components = dt_as_structure.getComponents(); //all components, even filler fields
		int struct_alignment=dt_as_structure.getAlignment();
		int num_of_components=dt_as_structure.getNumComponents();
		int total_size=dt_as_structure.getLength();
		boolean is_packed=dt_as_structure.isPackingEnabled();
		
		if (is_structure_empty(dt_as_structure)) 
		{
			String str_to_ret="//Structure "+name_of_struct+" has 0 components or reported as having 0 length\n";
			return str_to_ret;
		}
		
		String[] fieldnames = new String[num_of_components];
		String[] field_displaynames_for_types = new String[num_of_components];
		String[] field_descriptions_for_types = new String[num_of_components];
		int[] list_of_offsets_in_bytes=new int[num_of_components];
		int[] list_of_lengths_in_bytes=new int[num_of_components];
		boolean[] is_bitfied= new boolean[num_of_components];
		boolean[] component_returns_valid_hook= new boolean[num_of_components];
		boolean[] component_is_a_structure_that_was_excluded= new boolean[num_of_components];
		int last_position_of_component_which_returns_valid_hook=-1;
		
		/*Iterate over all components and store them into the arrays*/
		for (int i=0;i<num_of_components;i++)
		{
			DataTypeComponent dataTypeComponent=dt_as_structure.getComponent(i);
			String fieldname=dataTypeComponent.getFieldName();
			if ( fieldname==null || fieldname.strip().equals(""))
			{
				fieldnames[i]="unnamed_field_at_position_"+(i+1);
			}
			else
			{
				fieldnames[i]=fieldname.replaceAll("[^"+this.characters_allowed_in_variable_name+"]", "_");
			}
			/*
			 * Careful: both of these are written into a comment of the generated script, and both come from the database, which took
			 * them from the debugging information of the analysed file. Replacing the line feed alone used to be what was done here,
			 * and it is not enough: a carriage return ends a line of javascript on its own, as do the line separator and the
			 * paragraph separator, and these two are written at the end of a line that carries real code in front of them.
			 */
			field_displaynames_for_types[i]=HookGeneratorUtils.return_text_safe_for_a_javascript_comment(dataTypeComponent.getDataType().getDisplayName());
			field_descriptions_for_types[i]=HookGeneratorUtils.return_text_safe_for_a_javascript_comment(dataTypeComponent.getDataType().getDescription());
			list_of_offsets_in_bytes[i]=dataTypeComponent.getOffset();
			list_of_lengths_in_bytes[i]=dataTypeComponent.getLength();
			is_bitfied[i]=dataTypeComponent.isBitFieldComponent();
			component_is_a_structure_that_was_excluded[i]=false;
			if (dataTypeComponent.getDataType() instanceof Structure && !is_structure_empty((Structure) dataTypeComponent.getDataType()))
			{
				/*Careful: no member can be created for an excluded structure. Its class is never generated, so referring to it would only produce a javascript error when the hook runs*/
				if (is_structure_path_excluded(dataTypeComponent.getDataType().getPathName()))
				{
					component_returns_valid_hook[i]=false;
					component_is_a_structure_that_was_excluded[i]=true;
				}
				else
				{
					component_returns_valid_hook[i]=true;
					last_position_of_component_which_returns_valid_hook=i;
				}
			}
			else
			{
				component_returns_valid_hook[i]=false;
			}
		}
		
		hook_str ="class struct_"+name_of_struct+" {\n";
		hook_str+="    constructor(baseaddr) {\n";
		hook_str+="        this.alignment = "+struct_alignment+"\n";
		hook_str+="        this.is_packed = "+is_packed+"\n";
		hook_str+="        this.base = baseaddr\n";
		hook_str+="        this.total_size = "+total_size+"\n";
		hook_str+="        this.layout = {\n";
		
		for (int i=0;i<num_of_components;i++)
		{
			if (is_bitfied[i])
			{
				hook_str+="            //caution: field '"+fieldnames[i]+"' is a bitfield, access it carefully \n";
			}
			String addcomma=",";
			if (i==num_of_components-1)
			{
				addcomma=""; //do not add it at the end
			}
			hook_str+="            "+fieldnames[i]+" : this.base.add("+list_of_offsets_in_bytes[i]+")"+addcomma+"   //"+field_displaynames_for_types[i]+", size:"+list_of_lengths_in_bytes[i]+" - "+field_descriptions_for_types[i]+"\n";
		}
	
		hook_str+="        }\n";
		hook_str+="        this.offsets = {\n";
		
		for (int i=0;i<num_of_components;i++)
		{
			if (is_bitfied[i])
			{
				hook_str+="            //caution: field '"+fieldnames[i]+"' is a bitfield, access it carefully \n";
			}
			String addcomma=",";
			if (i==num_of_components-1)
			{
				addcomma=""; //do not add it at the end
			}
			hook_str+="            "+fieldnames[i]+" : "+list_of_offsets_in_bytes[i]+addcomma+"   //"+field_displaynames_for_types[i]+", size:"+list_of_lengths_in_bytes[i]+"\n";
		}
	
		hook_str+="        }\n";
		if (initialize_subcomponent_members && last_position_of_component_which_returns_valid_hook>-1) //check if at least one component will return a valid hook
		{
			hook_str+="        this.members = {\n";
			
			for (int i=0;i<num_of_components;i++)
			{
				String addcomma=",";
				if (component_is_a_structure_that_was_excluded[i])
				{
					hook_str+="            //no member is created for field '"+fieldnames[i]+"', its structure type was excluded and no class has been generated for it\n";
				}
				if (component_returns_valid_hook[i])
				{
					String full_name_of_component=dt_as_structure.getComponent(i).getDataType().getPathName().replaceAll("[^"+this.characters_allowed_in_variable_name+"]", "_");
					if (i==last_position_of_component_which_returns_valid_hook)
					{
						addcomma=""; //do not add it at the end
					}
					hook_str+="            "+fieldnames[i]+" : new struct_"+full_name_of_component+"(this.layout."+fieldnames[i]+")"+addcomma+"  \n";
				}		
			}
		
			hook_str+="        }\n";
		}
		hook_str+="    }\n";
		
		
		hook_str+="}\n\n";
		
		return hook_str;
	}
	
	public void handle_output(String incoming_hook_str)
	{
		//Print to eclipse console
		System.out.println(incoming_hook_str);

		//Copy to clipboard
		StringSelection stringSelection = new StringSelection(incoming_hook_str);
		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		clipboard.setContents(stringSelection, null);
						
		//Print to Ghidra Console	
		if (this.consoleService!=null)
		{
			this.consoleService.println(incoming_hook_str);
		}
		else
		{
			System.out.println("Can't print to console because consoleService is null");
		}
	}
	
	
}
