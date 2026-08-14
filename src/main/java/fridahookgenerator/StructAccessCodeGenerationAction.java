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
	protected Boolean is_recursive;
	private ConsoleService consoleService;
	private String characters_allowed_in_variable_name="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
	
	public StructAccessCodeGenerationAction(Plugin plugin, Boolean is_recursive) {
		super("Create_frida_offsets_for_struct", plugin.getName(), KeyBindingType.SHARED);
		this.incoming_plugin = plugin;
		this.current_program=null;
		this.is_recursive=is_recursive;
		init();
	}
	
	private void init() {
		if (this.is_recursive)
		{
			setPopupMenuData(
				new MenuData(new String[] { "Create Frida offsets for struct (and substructs)" }, null,"Frida-Hook"));
			setDescription("Generate Frida Offsets for this struct type and its contained substruct types (but not pointed struct types)");
		}
		else
		{
			setPopupMenuData(
					new MenuData(new String[] { "Create Frida offsets for struct (only this one)" }, null,"Frida-Hook"));
				setDescription("Generate Frida Offsets for this struct type");
		}
	}
	
	@Override
	public boolean isEnabledForContext(ActionContext context) {
		/*This function not only checks if the Struct offsets submenu should appear (be enabled), 
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
		
		
		/*
		 * Careful: the check on the type of the context above says nothing about the object that the context carries, as
		 * getContextObject() returns an Object and it is whoever created the context that decided what to put in it. The
		 * type of that object therefore has to be checked before it is cast. Using instanceof also takes care of a null
		 * context object, which would pass a cast and then fail on the line that follows it.
		 */
		Object contextObject = context.getContextObject();
		if (!(contextObject instanceof GTree)) {
			return false;
		}
		GTree gtree = (GTree) contextObject;
		/*Careful: getSelectionPaths() is documented to return null when nothing is selected, and this function is called by the framework all the time, including when nothing is selected*/
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths==null || selectionPaths.length != 1) {
			return false;
		}

		/*Careful: getLastPathComponent() returns an Object, so it is checked with instanceof and cast once. A DataTypeNode is a GTreeNode, so the intermediate cast to GTreeNode was one more cast that nothing was guarding*/
		Object last_component_of_the_selected_path=selectionPaths[0].getLastPathComponent();
		if (!(last_component_of_the_selected_path instanceof DataTypeNode)) {
			return false;
		}
		DataTypeNode dtNode = (DataTypeNode) last_component_of_the_selected_path;
		DataType dataType = dtNode.getDataType();
		//return dataType instanceof Composite || dataType instanceof Enum;
		return (dataType instanceof Composite && dataType instanceof Structure); 
	}

	@Override
	public void actionPerformed(ActionContext context) {

		/*
		 * These checks are the same ones that isEnabledForContext() has already made, and the action is only invoked when
		 * that returned true. They are repeated because the state is read again here instead of being carried over, and
		 * because a selection that changes in between must not bring the tool down.
		 */
		Object contextObject = context.getContextObject();
		if (!(contextObject instanceof GTree)) {
			System.out.println("The context of the action does not carry a GTree, no offsets are generated");
			return;
		}
		GTree gTree = (GTree) contextObject;
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		if (selectionPaths==null || selectionPaths.length!=1) {
			System.out.println("There is no single selected data type any more, no offsets are generated");
			return;
		}
		if (!(selectionPaths[0].getLastPathComponent() instanceof DataTypeNode)) {
			System.out.println("The selected node is not a data type, no offsets are generated");
			return;
		}
		final DataTypeNode dataTypeNode = (DataTypeNode) selectionPaths[0].getLastPathComponent();

		PluginTool tool = this.incoming_plugin.getTool();

		this.consoleService=tool.getService(ConsoleService.class); 
		
		
		DataType dt = dataTypeNode.getDataType();
		/*Careful: the same reasoning as above. isEnabledForContext() has already checked that this is a Structure, but the data type is read again here, so the check is repeated before the cast*/
		if (!(dt instanceof Structure)) {
			System.out.println("The selected data type is not a structure, no offsets are generated");
			return;
		}
		Structure dt_as_structure = (Structure) dt;
		
		
		StructAccessCodeGenerator structaccesscodegenerator=new StructAccessCodeGenerator(this.incoming_plugin.getTool(),this.current_program,dt_as_structure,new String[0],this.is_recursive,false,true);
		
		String hook_str=structaccesscodegenerator.generate_hook_str();  //this will also handle the output, as it is initialized with that option set to true
	}
	
	
	


}
