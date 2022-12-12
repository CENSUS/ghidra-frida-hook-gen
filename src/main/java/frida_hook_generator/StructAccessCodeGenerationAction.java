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


package frida_hook_generator;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.tree.TreePath;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingType;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.plugin.core.navigation.FindAppliedDataTypesService;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.table.GhidraTable;

public class StructAccessCodeGenerationAction extends DockingAction {

	protected Plugin incoming_plugin;
	protected Program current_program;
	private ConsoleService consoleService;
	private String characters_allowed_in_variable_name="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
	
	public StructAccessCodeGenerationAction(Plugin plugin) {
		super("Create_frida_offsets_for_struct", plugin.getName(), KeyBindingType.SHARED);
		this.incoming_plugin = plugin;
		this.current_program=null;
		init();
	}
	
	private void init() {
		setPopupMenuData(
			new MenuData(new String[] { "Create Frida offsets for struct" }, null,"Frida-Hook"));
		setDescription("Generate Frida Offsets for this struct");
	}
	
	@Override
	public boolean isEnabledForContext(ActionContext context) {
		/*This function not only checks if the Struct getters/setters submenu should appear (be enabled), 
		 * it also initializes the the "this.current_program" variable
		 */
		
		if (this.incoming_plugin==null)
		{
			return false;
		}
		
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		DataTypesActionContext context_as_DataTypesActionContext=(DataTypesActionContext)context;
		this.current_program=context_as_DataTypesActionContext.getProgram();
		if (this.current_program==null)
		{
			return false;
		}
		
		
		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths.length != 1) {
			return false;
		}

		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();
		if (!(node instanceof DataTypeNode)) {
			return false;
		}
		DataTypeNode dtNode = (DataTypeNode) node;
		DataType dataType = dtNode.getDataType();
		//return dataType instanceof Composite || dataType instanceof Enum;
		return (dataType instanceof Composite && dataType instanceof Structure); 
	}

	@Override
	public void actionPerformed(ActionContext context) {

		GTree gTree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		final DataTypeNode dataTypeNode = (DataTypeNode) selectionPaths[0].getLastPathComponent();

		PluginTool tool = this.incoming_plugin.getTool();

		this.consoleService=tool.getService(ConsoleService.class); 
		
		
		DataType dt = dataTypeNode.getDataType();
		Structure dt_as_structure = (Structure) dt;
		
		String hook_str=generate_hook_str(dt_as_structure);
		handle_output(hook_str);

	}
	
	
	private String generate_hook_str(Structure dt_as_structure)
	{
		
		String hook_str="";
		
		
		String name_of_struct=dt_as_structure.getName().replaceAll("[^"+this.characters_allowed_in_variable_name+"]", "_");
		
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
			field_displaynames_for_types[i]=dataTypeComponent.getDataType().getDisplayName();
			field_descriptions_for_types[i]=dataTypeComponent.getDataType().getDescription();
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
	
	protected void handle_output(String incoming_hook_str)
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
