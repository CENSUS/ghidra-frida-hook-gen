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
		
		
		StructAccessCodeGenerator structaccesscodegenerator=new StructAccessCodeGenerator(this.incoming_plugin.getTool(),this.current_program,dt_as_structure,false,false,true);
		
		String hook_str=structaccesscodegenerator.generate_hook_str();  //this will also handle the output, as it is initialized with that option set to true
	}
	
	
	


}
