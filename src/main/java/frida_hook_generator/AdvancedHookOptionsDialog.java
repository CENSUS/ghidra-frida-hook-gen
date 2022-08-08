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

import docking.DialogComponentProvider;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

import docking.ComponentProvider;
import docking.DialogComponentProvider;
import docking.widgets.OptionDialog;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import ghidra.app.util.AddEditDialog.NamespaceWrapper;
import ghidra.framework.cmd.Command;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;
import ghidra.util.layout.VerticalLayout;

public class AdvancedHookOptionsDialog extends DialogComponentProvider {
		
	private PluginTool tool;
	private TitledBorder nameBorder;
	protected JCheckBox ReferencestoAddressCheckBox;
	protected Boolean isReferencestoAddressCheckBoxchecked;
	protected JCheckBox ReferencestoFunctionCheckbox;
	protected Boolean isReferencestoFunctionCheckboxchecked;
	protected JCheckBox FunctionsReferencingFunctionCheckbox;
	protected Boolean isFunctionsReferencingFunctionCheckboxchecked;
	protected JCheckBox GenerateScriptCheckbox;
	protected Boolean isGenerateScriptCheckboxchecked;

	private Program current_program;
	private Address addr;

	public AdvancedHookOptionsDialog(String title, PluginTool tool) {
		super(title, true, true, true, false);
		this.tool = tool;
		this.isReferencestoAddressCheckBoxchecked=false;
		this.isReferencestoFunctionCheckboxchecked=false;
		this.isFunctionsReferencingFunctionCheckboxchecked=false;
		this.isGenerateScriptCheckboxchecked=false;
		

		addWorkPanel(create());
		setFocusComponent(ReferencestoAddressCheckBox);
		addOKButton();
		addCancelButton();
		setDefaultButton(okButton);
	}
	

	/**
	 * Define the Main panel for the dialog here.
	 */
	private JPanel create() {

		ReferencestoAddressCheckBox = new GCheckBox("Generate Hooks for addresses referencing the current address");
		ReferencestoAddressCheckBox.setMnemonic('A');
		ReferencestoAddressCheckBox.setToolTipText(
			"Generate Hooks for addresses referencing the current address");
		ReferencestoFunctionCheckbox = new GCheckBox("Generate Hooks for addresses referencing the current function");
		ReferencestoFunctionCheckbox.setMnemonic('F');
		ReferencestoFunctionCheckbox.setToolTipText("Generate Hooks for addresses referencing the current function");
		FunctionsReferencingFunctionCheckbox = new GCheckBox("Generate Hooks for functions referencing the current function");
		FunctionsReferencingFunctionCheckbox.setMnemonic('R');
		FunctionsReferencingFunctionCheckbox.setToolTipText(
			"Generate Hooks for functions referencing the current function");
		GenerateScriptCheckbox = new GCheckBox("Generate Hook Script and not Snippet");
		GenerateScriptCheckbox.setMnemonic('S');
		GenerateScriptCheckbox.setToolTipText(
				"Generate Hook Script and not Snippet, that means, add prologue and epilogue");

		JPanel mainPanel = new JPanel(new VerticalLayout(30));
		mainPanel.setPreferredSize(new Dimension(640,200));
		JPanel topPanel = new JPanel(new VerticalLayout(4));
		//JPanel midPanel = new JPanel(new BorderLayout());
		JPanel bottomPanel = new JPanel(new VerticalLayout(4));

		nameBorder =
			BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Reference options");
		topPanel.setBorder(nameBorder);
		
		Border scriptborder =
			BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Generate Script or Snippet");
		/*
		midPanel.setBorder(border);
		*/
		bottomPanel.setBorder(scriptborder);
		

		mainPanel.add(topPanel);
		//mainPanel.add(midPanel);
		mainPanel.add(bottomPanel);

		topPanel.add(ReferencestoAddressCheckBox,BorderLayout.NORTH);
		topPanel.add(ReferencestoFunctionCheckbox,BorderLayout.NORTH);
		topPanel.add(FunctionsReferencingFunctionCheckbox,BorderLayout.NORTH);

		bottomPanel.add(GenerateScriptCheckbox,BorderLayout.SOUTH);

		mainPanel.setBorder(new EmptyBorder(5, 5, 5, 5));

		return mainPanel;
	}


	public void fetch_advanced_hook_options(Address address, Program prog) {
		fetch_advanced_hook_options(address, prog, tool.getActiveWindow());
	}
	
	
	public void fetch_advanced_hook_options(Address address, Program targetProgram, Component centeredOverComponent) {
		initDialogForAdvancedHookOptions(targetProgram, address);
		tool.showDialog(this, centeredOverComponent);
	}
	
		
	
	private void initDialogForAdvancedHookOptions(Program p, Address address) {

		this.addr = address;
		this.current_program = p;

		setTitle("Create advanced Frida Hook regarding address " + address);
		ReferencestoAddressCheckBox.setEnabled(true);
		ReferencestoFunctionCheckbox.setEnabled(true);
		FunctionsReferencingFunctionCheckbox.setEnabled(true);
		//FunctionsReferencingFunctionCheckbox.setSelected(true);
		GenerateScriptCheckbox.setEnabled(true);
		GenerateScriptCheckbox.setSelected(false);

		clearStatusText();

	}
		
	protected void okCallback() {
		if (ReferencestoAddressCheckBox.isEnabled() && ReferencestoAddressCheckBox.isSelected()) {
			this.isReferencestoAddressCheckBoxchecked=true;
		}
		
		if (ReferencestoFunctionCheckbox.isEnabled() && ReferencestoFunctionCheckbox.isSelected()) {
			this.isReferencestoFunctionCheckboxchecked=true;
		}
		
		if (FunctionsReferencingFunctionCheckbox.isEnabled() && FunctionsReferencingFunctionCheckbox.isSelected()) {
			this.isFunctionsReferencingFunctionCheckboxchecked=true;
		}
		
		if (GenerateScriptCheckbox.isEnabled() && GenerateScriptCheckbox.isSelected()) {
			this.isGenerateScriptCheckboxchecked=true;
		}
		
		close();
	}
	

}

