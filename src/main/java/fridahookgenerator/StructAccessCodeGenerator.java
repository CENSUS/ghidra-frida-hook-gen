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
	
	public StructAccessCodeGenerator(PluginTool incoming_plugintool, Program current_program, Structure incoming_structure, 
			Boolean is_recursive_call , Boolean is_invoked_programmatically , Boolean should_output ) {
		
		this.incoming_plugintool=incoming_plugintool;
		this.current_program=current_program;
		this.incoming_structure=incoming_structure;
		this.is_recursive_call=is_recursive_call;
		this.included_structures=new HashMap<String,String>();
		this.is_invoked_programmatically_from_the_api=is_invoked_programmatically;
		this.should_output=should_output;		
		this.consoleService=incoming_plugintool.getService(ConsoleService.class); 
	}
	
	
	protected String generate_recursive_hook_str(Structure in_struct)
	{
		String hook_str="";
		DataTypeComponent[] components = in_struct.getComponents(); //all components, even filler fields
		
		for (int i=0;i<components.length;i++)
		{
			if (components[i].getDataType() instanceof Structure && !this.included_structures.containsKey(components[i].getDataType().getPathName())) 
			{
				String this_hook=generate_recursive_hook_str((Structure) components[i].getDataType());
				hook_str+=this_hook;
				this.included_structures.put(components[i].getDataType().getPathName(), this_hook);
			}
		}
		
		hook_str+=generate_hook_str_for_one_struct(in_struct);
		
		return hook_str;
		
	}
	
	
	public String generate_hook_str()
	{
		String hook_str="";
		
		if (!this.is_recursive_call)
		{
			hook_str+=generate_hook_str_for_one_struct(this.incoming_structure); 
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

	protected String generate_hook_str_for_one_struct(Structure dt_as_structure)
	{
		
		String hook_str="";
		
		
		String name_of_struct=dt_as_structure.getPathName().replaceAll("[^"+this.characters_allowed_in_variable_name+"]", "_");
		
		DataTypeComponent[] components = dt_as_structure.getComponents(); //all components, even filler fields
		int struct_alignment=dt_as_structure.getAlignment();
		int num_of_components=dt_as_structure.getNumComponents();
		int total_size=dt_as_structure.getLength();
		boolean is_packed=dt_as_structure.isPackingEnabled();
		
		if (num_of_components==0 || dt_as_structure.isZeroLength()) 
		{
			String str_to_ret="//Structure has 0 components or reported as having 0 length";
			return str_to_ret;
		}
		
		String[] fieldnames = new String[num_of_components];
		String[] field_displaynames_for_types = new String[num_of_components];
		String[] field_descriptions_for_types = new String[num_of_components];
		int[] list_of_offsets_in_bytes=new int[num_of_components];
		int[] list_of_lengths_in_bytes=new int[num_of_components];
		boolean[] is_bitfied= new boolean[num_of_components];
		
		/*Iterate over all components and store them into the arrays*/
		for (int i=0;i<num_of_components;i++)
		{
			DataTypeComponent dataTypeComponent=dt_as_structure.getComponent(i);
			String fieldname=dataTypeComponent.getFieldName();
			if (fieldname!=null)
			{
				fieldnames[i]=fieldname.replaceAll("[^"+this.characters_allowed_in_variable_name+"]", "_");
			}
			else
			{
				fieldnames[i]="unnamed_field_at_position_"+(i+1);
			}
			field_displaynames_for_types[i]=dataTypeComponent.getDataType().getDisplayName().replace("\n", " ");
			field_descriptions_for_types[i]=dataTypeComponent.getDataType().getDescription().replace("\n", " ");
			list_of_offsets_in_bytes[i]=dataTypeComponent.getOffset();
			list_of_lengths_in_bytes[i]=dataTypeComponent.getLength();
			is_bitfied[i]=dataTypeComponent.isBitFieldComponent();
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
