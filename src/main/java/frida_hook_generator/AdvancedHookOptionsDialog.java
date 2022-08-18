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
import javax.swing.ButtonGroup;
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
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GLabel;
import ghidra.app.util.AddEditDialog.NamespaceWrapper;
import ghidra.framework.cmd.Command;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;
import ghidra.util.layout.HorizontalLayout;
import ghidra.util.layout.VerticalLayout;

public class AdvancedHookOptionsDialog extends DialogComponentProvider {
		
	private PluginTool tool;
	protected Boolean isOKpressed;
	
	
	/*Incoming References items*/
	protected JCheckBox ReferencestoAddressCheckBox;
	protected Boolean isReferencestoAddressCheckBoxchecked;
	protected JCheckBox FunctionsReferencingAddressCheckBox;
	protected Boolean isFunctionsReferencingAddressCheckBoxchecked;
	protected JCheckBox ReferencestoFunctionCheckbox;
	protected Boolean isReferencestoFunctionCheckboxchecked;
	protected JCheckBox FunctionsReferencingFunctionCheckbox;
	protected Boolean isFunctionsReferencingFunctionCheckboxchecked;
	protected JComboBox<String> InFunctionReferenceDepthcomboBox;
	
	/*Outgoing References items*/
	protected JCheckBox OutReferencesfromFunctionCheckBox;
	protected Boolean isOutReferencesfromFunctionCheckBoxchecked;
	protected JComboBox<String> OutFunctionReferenceDepthcomboBox;
	
	/*Range items*/
	protected JCheckBox RangeAddressesCheckBox;
	protected Boolean isRangeAddressesCheckBoxchecked;
	protected JCheckBox RangeFunctionsCheckBox;
	protected Boolean isRangeFunctionsCheckBoxchecked;
	protected GLabel RangeAddressesNumLabel;
	protected JTextField RangeAddressesNumTextField;
	protected int RangeAddressesNum;
	protected GLabel RangeFunctionsNumLabel;
	protected JTextField RangeFunctionsNumTextField;
	protected int RangeFunctionsNum;
	protected ButtonGroup RangeAddressesButtonGroup;
	protected GRadioButton RangeAddressesRadioButtonAddr;
	protected GRadioButton RangeAddressesRadioButtonInstr;
	protected GRadioButton RangeAddressesRadioButtonFun;
	protected ButtonGroup RangeFunctionsButtonGroup;
	protected GRadioButton RangeFunctionsRadioButtonAddr;
	protected GRadioButton RangeFunctionsRadioButtonInstr;
	protected GRadioButton RangeFunctionsRadioButtonFun;
	protected JCheckBox FunctionRegexCheckBox;
	protected Boolean isFunctionRegexCheckBoxchecked;
	protected JTextField FunctionRegexTextField;
	
	/*Output items*/
	protected JCheckBox OutputReasonForHookGenCheckbox;
	protected Boolean isOutputReasonForHookGenCheckboxchecked;
	protected JComboBox<String> ReasonForHookGenAmountcomboBox;
	protected JCheckBox GenerateScriptCheckbox;
	protected Boolean isGenerateScriptCheckboxchecked;
	protected JComboBox<String> TypeofScriptGenerationcomboBox;
	protected JCheckBox CustomFunInterceptorHookOutputCheckbox;
	protected Boolean isCustomFunInterceptorHookOutputCheckboxchecked;
	protected JComboBox<String> CustomFunInterceptorHookOutputcomboBox;
	protected JCheckBox DoNotIncludeFunParamscheckbox;
	protected Boolean isDoNotIncludeFunParamscheckboxchecked;

	private Program current_program;
	private Address addr;

	public AdvancedHookOptionsDialog(String title, PluginTool tool) {
		super(title, true, true, true, false);
		this.tool = tool;
		this.isOKpressed=false;
		this.isReferencestoAddressCheckBoxchecked=false;
		this.isFunctionsReferencingAddressCheckBoxchecked=false;
		this.isReferencestoFunctionCheckboxchecked=false;
		this.isFunctionsReferencingFunctionCheckboxchecked=false;
		this.isGenerateScriptCheckboxchecked=false;
		this.isRangeAddressesCheckBoxchecked=false;
		this.isRangeFunctionsCheckBoxchecked=false;
		this.isOutReferencesfromFunctionCheckBoxchecked=false;
		this.isOutputReasonForHookGenCheckboxchecked=false;
		this.isCustomFunInterceptorHookOutputCheckboxchecked=false;
		this.isDoNotIncludeFunParamscheckboxchecked=false;
		this.isFunctionRegexCheckBoxchecked=false;

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

		ReferencestoAddressCheckBox = new GCheckBox("Generate Hooks for addresses (statically) referencing the current address");
		ReferencestoAddressCheckBox.setToolTipText(
			"Generate Hooks for addresses referencing the current address");
		FunctionsReferencingAddressCheckBox = new GCheckBox("Generate Hooks for functions containing code that (statically) references the current address");
		FunctionsReferencingAddressCheckBox.setToolTipText("Generate Hooks for functions containing code that (statically) references the current address");
		ReferencestoFunctionCheckbox = new GCheckBox("Generate Hooks for addresses (statically) referencing the current function");
		ReferencestoFunctionCheckbox.setToolTipText("Generate Hooks for addresses referencing the current function");
		FunctionsReferencingFunctionCheckbox = new GCheckBox("Generate Hooks for functions (statically) referencing the current function for depth");
		FunctionsReferencingFunctionCheckbox.setMnemonic('R');
		FunctionsReferencingFunctionCheckbox.setToolTipText(
			"Generate Hooks for functions referencing the current function for a certain depth");
		String[] indepths_to_choose_from= {"1","2","3","4","5","6","7","8","9","10"};
		InFunctionReferenceDepthcomboBox=new JComboBox<>(indepths_to_choose_from);
		
		
		OutReferencesfromFunctionCheckBox = new GCheckBox("Generate Hooks for functions (statically) called by the current function for depth");
		OutReferencesfromFunctionCheckBox.setToolTipText(
				"Generate Hooks for functions (statically) called by the current function for a certain depth");
		String[] outdepths_to_choose_from= {"1","2","3","4","5","6","7","8","9","10"};
		OutFunctionReferenceDepthcomboBox=new JComboBox<>(outdepths_to_choose_from);
		
		
		
		RangeAddressesCheckBox = new GCheckBox("Generate Hooks for addresses (starting from current address, and moving forward for X elements) (SLOW)");
		RangeAddressesCheckBox.setToolTipText("This option includes the current address in the list of possible hooks, and counts it as the 1st");
		RangeFunctionsCheckBox = new GCheckBox("Generate Hooks for functions (starting from current address, and moving forward for X elements)");
		RangeFunctionsCheckBox.setToolTipText("This option includes the current function (if the current address is in one) in the list of possible hooks, and counts it as the 1st");
		RangeAddressesNumLabel=new GLabel("Number and type of elements:");
		RangeAddressesNumTextField=new JTextField(10);
		RangeFunctionsNumLabel=new GLabel("Number and type of elements:");
		RangeFunctionsNumTextField=new JTextField(10);
		RangeAddressesButtonGroup= new ButtonGroup();
		RangeFunctionsButtonGroup= new ButtonGroup();
		RangeAddressesRadioButtonAddr = new GRadioButton("Addresses (Bytes) (max 200k)");
		RangeAddressesRadioButtonInstr = new GRadioButton("Instructions (max 100k)");
		RangeAddressesRadioButtonFun = new GRadioButton("Functions (max 1000)");
		RangeAddressesButtonGroup.add(RangeAddressesRadioButtonAddr);
		RangeAddressesButtonGroup.add(RangeAddressesRadioButtonInstr);
		RangeAddressesButtonGroup.add(RangeAddressesRadioButtonFun);
		RangeFunctionsRadioButtonAddr = new GRadioButton("Addresses (Bytes)");
		RangeFunctionsRadioButtonInstr = new GRadioButton("Instructions");
		RangeFunctionsRadioButtonFun = new GRadioButton("Functions");
		RangeFunctionsButtonGroup.add(RangeFunctionsRadioButtonAddr);
		RangeFunctionsButtonGroup.add(RangeFunctionsRadioButtonInstr);
		RangeFunctionsButtonGroup.add(RangeFunctionsRadioButtonFun);
		RangeAddressesRadioButtonFun.setSelected(true);
		RangeFunctionsRadioButtonFun.setSelected(true);
		FunctionRegexCheckBox=new GCheckBox("Generate hooks for functions whose name matches the following (case insensitive) regular expression:");
		FunctionRegexCheckBox.setToolTipText("In the case where the function names are known, similarly named functions may fall under the same functional block, and hooking all of them can be useful");
		FunctionRegexTextField=new JTextField(10);
		
		OutputReasonForHookGenCheckbox = new GCheckBox("Print the reason(s) why each hook is generated, maximum number of reasons:");
		OutputReasonForHookGenCheckbox.setToolTipText(
				"This option prints the reasons why every hook is generated. There might be multiple if an address is asked to be hooked multiple times in the same batch.");
		String[] Amount_of_reasons_choices= {"1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30"};
		ReasonForHookGenAmountcomboBox=new JComboBox<>(Amount_of_reasons_choices);
		ReasonForHookGenAmountcomboBox.setSelectedIndex(9);
		
		CustomFunInterceptorHookOutputCheckbox = new GCheckBox("In case of hook generation for functions:");
		CustomFunInterceptorHookOutputCheckbox.setToolTipText("This option allows to modify the way the function interceptor hook generation is done");
		String[] ways_to_alter_function_interceptor_hook= {"Do not include onEnter()","Do not include onLeave()"};
		CustomFunInterceptorHookOutputcomboBox=new JComboBox<>(ways_to_alter_function_interceptor_hook);
		
		DoNotIncludeFunParamscheckbox=new GCheckBox("In case of hook generation for functions, do not print their parameters in the console");
		DoNotIncludeFunParamscheckbox.setToolTipText("In case of hook generation for functions, do not print their parameters in the console");	
		
		GenerateScriptCheckbox = new GCheckBox("Generate Hook Script and not Snippet, registering interceptors through method ");
		GenerateScriptCheckbox.setMnemonic('S');
		GenerateScriptCheckbox.setToolTipText(
				"Generate Hook Script and not Snippet, that means, add prologue and epilogue");
		String[] ways_for_script_generation={"Default method that waits 2s", "dlopen() method (EXPERIMENTAL)"};
		TypeofScriptGenerationcomboBox=new JComboBox<>(ways_for_script_generation);
		

		JPanel mainPanel = new JPanel(new VerticalLayout(30));
		mainPanel.setPreferredSize(new Dimension(750,400));
		JPanel referencesPanel = new JPanel(new VerticalLayout(4));
		JPanel referencessubPanel = new JPanel(new HorizontalLayout(4));
		JPanel outreferencesPanel = new JPanel(new VerticalLayout(4));
		JPanel outreferencessubPanel = new JPanel(new HorizontalLayout(4));
		JPanel rangePanel = new JPanel(new VerticalLayout(4));
		JPanel rangeSubPanel1 = new JPanel(new HorizontalLayout(4));
		JPanel rangeSubPanel2 = new JPanel(new HorizontalLayout(4));
		JPanel rangeSubPanel3 = new JPanel(new HorizontalLayout(4));
		JPanel outputPanel = new JPanel(new VerticalLayout(4));
		JPanel outputSubPanel1 = new JPanel(new HorizontalLayout(4));
		JPanel outputSubPanel2 = new JPanel(new HorizontalLayout(4));
		JPanel outputSubPanel3 = new JPanel(new HorizontalLayout(4));
		
		TitledBorder referenceBorder =
			BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Incoming Reference options");
		referencesPanel.setBorder(referenceBorder);
		
		TitledBorder outreferenceBorder =
				BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Outgoing Reference options");
			outreferencesPanel.setBorder(outreferenceBorder);
		
		TitledBorder rangeBorder =
				BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Range options");
		rangePanel.setBorder(rangeBorder);
		
		TitledBorder outputborder =
			BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Output Options");
		outputPanel.setBorder(outputborder);
		

		mainPanel.add(referencesPanel);
		mainPanel.add(outreferencesPanel);
		mainPanel.add(rangePanel);
		mainPanel.add(outputPanel);

		referencesPanel.add(ReferencestoAddressCheckBox,BorderLayout.NORTH);
		referencesPanel.add(FunctionsReferencingAddressCheckBox,BorderLayout.NORTH);
		referencesPanel.add(ReferencestoFunctionCheckbox,BorderLayout.NORTH);
		referencessubPanel.add(FunctionsReferencingFunctionCheckbox,BorderLayout.NORTH);
		referencessubPanel.add(InFunctionReferenceDepthcomboBox);
		referencesPanel.add(referencessubPanel);

		
		outreferencessubPanel.add(OutReferencesfromFunctionCheckBox,BorderLayout.NORTH);
		outreferencessubPanel.add(OutFunctionReferenceDepthcomboBox,BorderLayout.NORTH);
		outreferencesPanel.add(outreferencessubPanel);

		rangePanel.add(RangeAddressesCheckBox);
		rangeSubPanel1.add(RangeAddressesNumLabel);
		rangeSubPanel1.add(RangeAddressesNumTextField);
		rangeSubPanel1.add(RangeAddressesRadioButtonAddr);
		rangeSubPanel1.add(RangeAddressesRadioButtonInstr);
		rangeSubPanel1.add(RangeAddressesRadioButtonFun);
		rangePanel.add(rangeSubPanel1);
		rangePanel.add(RangeFunctionsCheckBox);
		rangeSubPanel2.add(RangeFunctionsNumLabel);
		rangeSubPanel2.add(RangeFunctionsNumTextField);
		rangeSubPanel2.add(RangeFunctionsRadioButtonAddr);
		//rangeSubPanel2.add(RangeFunctionsRadioButtonInstr);
		rangeSubPanel2.add(RangeFunctionsRadioButtonFun);
		rangePanel.add(rangeSubPanel2);
		rangeSubPanel3.add(FunctionRegexCheckBox);
		rangeSubPanel3.add(FunctionRegexTextField);
		rangePanel.add(rangeSubPanel3);
		
		outputSubPanel1.add(OutputReasonForHookGenCheckbox);
		outputSubPanel1.add(ReasonForHookGenAmountcomboBox);
		outputSubPanel2.add(CustomFunInterceptorHookOutputCheckbox);
		outputSubPanel2.add(CustomFunInterceptorHookOutputcomboBox);
		outputSubPanel3.add(GenerateScriptCheckbox);
		outputSubPanel3.add(TypeofScriptGenerationcomboBox);
		outputPanel.add(outputSubPanel1,BorderLayout.NORTH);
		outputPanel.add(outputSubPanel2,BorderLayout.NORTH);
		outputPanel.add(DoNotIncludeFunParamscheckbox,BorderLayout.NORTH);
		outputPanel.add(outputSubPanel3,BorderLayout.NORTH);

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
		FunctionsReferencingAddressCheckBox.setEnabled(true);
		ReferencestoFunctionCheckbox.setEnabled(true);
		OutReferencesfromFunctionCheckBox.setEnabled(true);
		FunctionsReferencingFunctionCheckbox.setEnabled(true);
		GenerateScriptCheckbox.setEnabled(true);
		GenerateScriptCheckbox.setSelected(false);
		RangeAddressesCheckBox.setEnabled(true);
		RangeFunctionsCheckBox.setEnabled(true);
		OutputReasonForHookGenCheckbox.setEnabled(true);
		CustomFunInterceptorHookOutputCheckbox.setEnabled(true);
		DoNotIncludeFunParamscheckbox.setEnabled(true);
		FunctionRegexCheckBox.setEnabled(true);
		

		clearStatusText();

	}
		
	protected void okCallback() {
		this.isOKpressed=true;
		
		if (ReferencestoAddressCheckBox.isEnabled() && ReferencestoAddressCheckBox.isSelected()) {
			this.isReferencestoAddressCheckBoxchecked=true;
		}
		
		if (FunctionsReferencingAddressCheckBox.isEnabled() && FunctionsReferencingAddressCheckBox.isSelected()) {
			this.isFunctionsReferencingAddressCheckBoxchecked=true;
		}
		
		if (ReferencestoFunctionCheckbox.isEnabled() && ReferencestoFunctionCheckbox.isSelected()) {
			this.isReferencestoFunctionCheckboxchecked=true;
		}
		
		if (FunctionsReferencingFunctionCheckbox.isEnabled() && FunctionsReferencingFunctionCheckbox.isSelected()) {
			this.isFunctionsReferencingFunctionCheckboxchecked=true;
		}
		
		if (OutReferencesfromFunctionCheckBox.isEnabled() && OutReferencesfromFunctionCheckBox.isSelected()) {
			this.isOutReferencesfromFunctionCheckBoxchecked=true;
		}
		
		if (GenerateScriptCheckbox.isEnabled() && GenerateScriptCheckbox.isSelected()) {
			this.isGenerateScriptCheckboxchecked=true;
		}
		if (OutputReasonForHookGenCheckbox.isEnabled() && OutputReasonForHookGenCheckbox.isSelected()) {
			this.isOutputReasonForHookGenCheckboxchecked=true;
		}
		
		if (RangeAddressesCheckBox.isEnabled() && RangeAddressesCheckBox.isSelected()) {
			this.isRangeAddressesCheckBoxchecked=true;
			RangeAddressesNum=0;
			try {
				long tmplong=(int)Long.parseLong(RangeAddressesNumTextField.getText());
				if (tmplong>2000000000)
				{
					RangeAddressesNum=2000000000;
				}
				else
				{
					RangeAddressesNum=(int)tmplong;
				}
			}
			catch (NumberFormatException ex)
			{
				RangeAddressesNum=0;
			}
			if (RangeAddressesNum<0)
			{
				RangeAddressesNum=0;
			}
			if (RangeAddressesRadioButtonAddr.isSelected() && RangeAddressesNum>200000)
			{
				RangeAddressesNum=200000;
			}
			if (RangeAddressesRadioButtonInstr.isSelected() && RangeAddressesNum>100000)
			{
				RangeAddressesNum=100000;
			}
			if (RangeAddressesRadioButtonFun.isSelected() && RangeAddressesNum>1000)
			{
				RangeAddressesNum=1000;
			}
			
		}
		
		if (RangeFunctionsCheckBox.isEnabled() && RangeFunctionsCheckBox.isSelected()) {
			this.isRangeFunctionsCheckBoxchecked=true;
			RangeFunctionsNum=0;
			RangeFunctionsNum=0;
			try {
				long tmplong=Long.parseLong(RangeFunctionsNumTextField.getText());
				if (tmplong>2000000000)
				{
					RangeFunctionsNum=2000000000;
				}
				else
				{
					RangeFunctionsNum=(int)tmplong;
				}
			}
			catch (NumberFormatException ex)
			{
				RangeFunctionsNum=0;
			}
			if (RangeFunctionsNum<0)
			{
				RangeFunctionsNum=0;
			}
		}
		if (FunctionRegexCheckBox.isEnabled() && FunctionRegexCheckBox.isSelected()) {
			this.isFunctionRegexCheckBoxchecked=true;
		}
		if (CustomFunInterceptorHookOutputCheckbox.isEnabled() && CustomFunInterceptorHookOutputCheckbox.isSelected()) {
			this.isCustomFunInterceptorHookOutputCheckboxchecked=true;
		}
		if (DoNotIncludeFunParamscheckbox.isEnabled() && DoNotIncludeFunParamscheckbox.isSelected()) {
			this.isDoNotIncludeFunParamscheckboxchecked=true;
		}
		
		
		
		close();
	}
	

}

