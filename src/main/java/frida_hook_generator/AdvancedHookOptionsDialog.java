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
	protected Boolean is_invoked_from_selecting_multiple_addresses;
	
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
	protected JCheckBox OutReferencesfromAddressCheckBox;
	protected Boolean isOutReferencesfromAddressCheckBoxchecked;
	protected JCheckBox OutDynamicCallReferencesfromFunctionCheckBox;
	protected Boolean isOutDynamicCallReferencesfromFunctionCheckBoxchecked;
	protected JCheckBox OutDynamicCallReferencesfromAddressCheckBox;
	protected Boolean isOutDynamicCallReferencesfromAddressCheckBoxchecked;
	
	/*Range items*/
	protected JCheckBox HookThisAddressCheckBox;
	protected Boolean isHookThisAddressCheckBoxchecked;
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
	protected GRadioButton RangeFunctionsRadioButtonFunBackwards;
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
	protected JCheckBox IncludeCustomTextcheckbox;
	protected Boolean isIncludeCustomTextcheckboxchecked;
	protected JTextField IncludeCustomTextTextField;
	protected JCheckBox GenerateBacktraceCheckbox;
	protected Boolean isGenerateBacktraceCheckboxchecked;
	protected JComboBox<String> GenerateBacktracecomboBox;

	private Program current_program;
	private Address addr;

	public AdvancedHookOptionsDialog(String title, PluginTool tool, Program current_program,Boolean is_invoked_from_selecting_multiple_addresses) {
		super(title, true, true, true, false);
		this.tool = tool;
		this.current_program=current_program;
		this.isOKpressed=false;
		this.is_invoked_from_selecting_multiple_addresses=is_invoked_from_selecting_multiple_addresses;
		this.isReferencestoAddressCheckBoxchecked=false;
		this.isFunctionsReferencingAddressCheckBoxchecked=false;
		this.isReferencestoFunctionCheckboxchecked=false;
		this.isFunctionsReferencingFunctionCheckboxchecked=false;
		this.isGenerateScriptCheckboxchecked=false;
		this.isHookThisAddressCheckBoxchecked=false;
		this.isRangeAddressesCheckBoxchecked=false;
		this.isRangeFunctionsCheckBoxchecked=false;
		this.isOutReferencesfromFunctionCheckBoxchecked=false;
		this.isOutReferencesfromAddressCheckBoxchecked=false;
		this.isOutputReasonForHookGenCheckboxchecked=false;
		this.isCustomFunInterceptorHookOutputCheckboxchecked=false;
		this.isDoNotIncludeFunParamscheckboxchecked=false;
		this.isFunctionRegexCheckBoxchecked=false;
		this.isGenerateBacktraceCheckboxchecked=false;
		this.isIncludeCustomTextcheckboxchecked=false;
		this.isOutDynamicCallReferencesfromFunctionCheckBoxchecked=false;
		this.isOutDynamicCallReferencesfromAddressCheckBoxchecked=false;
		
		addWorkPanel(create());
		setFocusComponent(ReferencestoAddressCheckBox);
		addOKButton();
		addCancelButton();
		setDefaultButton(okButton);
	}
	

	

	/**
	 * Define the Main panel for the dialog.
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
		OutReferencesfromAddressCheckBox = new GCheckBox("Generate Hooks for the addresses (statically) referenced by the current address");
		OutReferencesfromAddressCheckBox.setToolTipText(
				"Generate Hooks for the addresses (statically) referenced by the current address. Appears only during selection of multiple addresses");
		OutDynamicCallReferencesfromAddressCheckBox = new GCheckBox("For every instruction to be hooked, if it is a dynamic (computed) call, print which address the execution will land on (X64,AARCH64 only)");
		OutDynamicCallReferencesfromAddressCheckBox.setToolTipText("For every instruction to be hooked, if it is a dynamic (computed) call, print which address the execution will land on (X64,AARCH64 only)");
		OutDynamicCallReferencesfromFunctionCheckBox = new GCheckBox("For each dynamic (computed) call in current function, print which address the execution will land on when this call is executed (X64,AARCH64 only)");
		OutDynamicCallReferencesfromFunctionCheckBox.setToolTipText("For each dynamic (computed) call in current function, print which address the execution will land on when this call is executed (X64,AARCH64 only)");

		
		HookThisAddressCheckBox = new GCheckBox("Generate a Hook for this (the current) address, through which this dialog was spawned");
		RangeAddressesCheckBox = new GCheckBox("Generate Hooks for addresses (starting from current address, and moving forward for X elements)");
		RangeAddressesCheckBox.setToolTipText("This option includes the current address in the list of possible hooks, and counts it as the 1st");
		RangeFunctionsCheckBox = new GCheckBox("Generate Hooks for functions (starting from current address, and moving for X elements)");
		RangeFunctionsCheckBox.setToolTipText("This option includes the current function (if the current address is in one) in the list of possible hooks, and counts it as the 1st");
		RangeAddressesNumLabel=new GLabel("Number and type of elements:");
		RangeAddressesNumTextField=new JTextField(10);
		RangeFunctionsNumLabel=new GLabel("Number and type of elements:");
		RangeFunctionsNumTextField=new JTextField(10);
		RangeAddressesButtonGroup= new ButtonGroup();
		RangeFunctionsButtonGroup= new ButtonGroup();
		RangeAddressesRadioButtonAddr = new GRadioButton("Addresses (Bytes)");
		RangeAddressesRadioButtonInstr = new GRadioButton("Instructions");
		RangeAddressesRadioButtonFun = new GRadioButton("Functions");
		RangeAddressesButtonGroup.add(RangeAddressesRadioButtonAddr);
		RangeAddressesButtonGroup.add(RangeAddressesRadioButtonInstr);
		RangeAddressesButtonGroup.add(RangeAddressesRadioButtonFun);
		RangeFunctionsRadioButtonAddr = new GRadioButton("Addresses (Bytes) (forward)");
		RangeFunctionsRadioButtonInstr = new GRadioButton("Instructions");
		RangeFunctionsRadioButtonFun = new GRadioButton("Functions (forward)");
		RangeFunctionsRadioButtonFunBackwards = new GRadioButton("Functions (backwards)");
		RangeFunctionsButtonGroup.add(RangeFunctionsRadioButtonAddr);
		RangeFunctionsButtonGroup.add(RangeFunctionsRadioButtonInstr);
		RangeFunctionsButtonGroup.add(RangeFunctionsRadioButtonFun);
		RangeFunctionsButtonGroup.add(RangeFunctionsRadioButtonFunBackwards);
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
		String[] ways_to_alter_function_interceptor_hook= {"Do not include onEnter()","Do not include onLeave()","use Interceptor.replace() (EXPERIMENTAL!)"};
		CustomFunInterceptorHookOutputcomboBox=new JComboBox<>(ways_to_alter_function_interceptor_hook);
		
		DoNotIncludeFunParamscheckbox=new GCheckBox("In case of hook generation for functions, do not print their parameters");
		DoNotIncludeFunParamscheckbox.setToolTipText("In case of hook generation for functions, do not print their parameters");	
		
		IncludeCustomTextcheckbox=new GCheckBox("Add the following javascript code in every hook generated:");
		IncludeCustomTextcheckbox.setToolTipText("Adds javascript code in every hook, at the start (not present in function hook if onEnter() is removed)");
		IncludeCustomTextTextField=new JTextField(30);
		
		GenerateBacktraceCheckbox=new GCheckBox("Generate backtrace:");
		GenerateBacktraceCheckbox.setToolTipText("Generate a backtrace through the methods provided by frida (not present in function hook if onEnter() is removed)");	
		String[] ways_to_generate_backtrace= {"Backtracer.ACCURATE at function beginnings","Backtracer.FUZZY at function beginnings","Backtracer.ACCURATE in every hook","Backtracer.FUZZY in every hook"};
		GenerateBacktracecomboBox=new JComboBox<>(ways_to_generate_backtrace);

		
		GenerateScriptCheckbox = new GCheckBox("Generate Hook Script and not Snippet, registering interceptors through method ");
		GenerateScriptCheckbox.setMnemonic('S');
		GenerateScriptCheckbox.setToolTipText(
				"Generate Hook Script and not Snippet, that means, add prologue and epilogue");
		String[] ways_for_script_generation={"Default method that waits 2s", "dlopen() method (EXPERIMENTAL)", "LoadLibrary() method (EXPERIMENTAL)"};
		TypeofScriptGenerationcomboBox=new JComboBox<>(ways_for_script_generation);
		

		JPanel mainPanel = new JPanel(new VerticalLayout(30));
		mainPanel.setPreferredSize(new Dimension(750,430));
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
		JPanel outputSubPanel4 = new JPanel(new HorizontalLayout(4));
		JPanel outputSubPanel5 = new JPanel(new HorizontalLayout(4));
		
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
		if (is_invoked_from_selecting_multiple_addresses)
		{
			outreferencesPanel.add(OutReferencesfromAddressCheckBox);
		}
		//currently, dynamic hooking is not provided
		if (false && (this.current_program.getLanguage().getLanguageID().toString().indexOf("AARCH64:LE:64")>=0 || this.current_program.getLanguage().getLanguageID().toString().indexOf("x86:LE:64")>=0))
		{
			outreferencesPanel.add(OutDynamicCallReferencesfromAddressCheckBox);
			outreferencesPanel.add(OutDynamicCallReferencesfromFunctionCheckBox);
		}
		
		
		rangePanel.add(HookThisAddressCheckBox);
		if (is_invoked_from_selecting_multiple_addresses)
		{
			rangePanel.add(RangeAddressesCheckBox);
			rangeSubPanel1.add(RangeAddressesNumLabel);
			rangeSubPanel1.add(RangeAddressesNumTextField);
			rangeSubPanel1.add(RangeAddressesRadioButtonAddr);
			rangeSubPanel1.add(RangeAddressesRadioButtonInstr);
			rangeSubPanel1.add(RangeAddressesRadioButtonFun);
			rangePanel.add(rangeSubPanel1);
		}
		rangePanel.add(RangeFunctionsCheckBox);
		rangeSubPanel2.add(RangeFunctionsNumLabel);
		rangeSubPanel2.add(RangeFunctionsNumTextField);
		rangeSubPanel2.add(RangeFunctionsRadioButtonAddr);
		//rangeSubPanel2.add(RangeFunctionsRadioButtonInstr);  //Not implemented
		rangeSubPanel2.add(RangeFunctionsRadioButtonFun);
		rangeSubPanel2.add(RangeFunctionsRadioButtonFunBackwards);
		rangePanel.add(rangeSubPanel2);
		if (!is_invoked_from_selecting_multiple_addresses)
		{
			rangeSubPanel3.add(FunctionRegexCheckBox);
			rangeSubPanel3.add(FunctionRegexTextField);
			rangePanel.add(rangeSubPanel3);
		}
		
		outputSubPanel1.add(OutputReasonForHookGenCheckbox);
		outputSubPanel1.add(ReasonForHookGenAmountcomboBox);
		outputSubPanel2.add(CustomFunInterceptorHookOutputCheckbox);
		outputSubPanel2.add(CustomFunInterceptorHookOutputcomboBox);
		outputSubPanel3.add(GenerateBacktraceCheckbox);
		outputSubPanel3.add(GenerateBacktracecomboBox);
		outputSubPanel4.add(IncludeCustomTextcheckbox);
		outputSubPanel4.add(IncludeCustomTextTextField);
		outputSubPanel5.add(GenerateScriptCheckbox);
		outputSubPanel5.add(TypeofScriptGenerationcomboBox);
		outputPanel.add(outputSubPanel1,BorderLayout.NORTH);
		outputPanel.add(outputSubPanel2,BorderLayout.NORTH);
		outputPanel.add(outputSubPanel3,BorderLayout.NORTH);
		outputPanel.add(DoNotIncludeFunParamscheckbox,BorderLayout.NORTH);
		outputPanel.add(outputSubPanel4,BorderLayout.NORTH);
		outputPanel.add(outputSubPanel5,BorderLayout.NORTH);
		
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

		if (!is_invoked_from_selecting_multiple_addresses)
		{
			setTitle("Create advanced Frida Hook regarding address " + address);
		}
		else
		{
			//address will be null in this case
			setTitle("Generate advanced Frida Hooks for selection");
		}
		ReferencestoAddressCheckBox.setEnabled(true);
		FunctionsReferencingAddressCheckBox.setEnabled(true);
		ReferencestoFunctionCheckbox.setEnabled(true);
		OutReferencesfromFunctionCheckBox.setEnabled(true);
		OutReferencesfromAddressCheckBox.setEnabled(true);
		FunctionsReferencingFunctionCheckbox.setEnabled(true);
		GenerateScriptCheckbox.setEnabled(true);
		GenerateScriptCheckbox.setSelected(false);
		HookThisAddressCheckBox.setEnabled(true);
		HookThisAddressCheckBox.setSelected(true); //by default, this one is true
		RangeAddressesCheckBox.setEnabled(true);
		RangeFunctionsCheckBox.setEnabled(true);
		OutputReasonForHookGenCheckbox.setEnabled(true);
		CustomFunInterceptorHookOutputCheckbox.setEnabled(true);
		DoNotIncludeFunParamscheckbox.setEnabled(true);
		IncludeCustomTextcheckbox.setEnabled(true);
		FunctionRegexCheckBox.setEnabled(true);
		GenerateBacktraceCheckbox.setEnabled(true);
		IncludeCustomTextcheckbox.setEnabled(true);
		OutDynamicCallReferencesfromFunctionCheckBox.setEnabled(true);
		OutDynamicCallReferencesfromAddressCheckBox.setEnabled(true);

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
		
		if (OutReferencesfromAddressCheckBox.isEnabled() && OutReferencesfromAddressCheckBox.isSelected()) {
			this.isOutReferencesfromAddressCheckBoxchecked=true;
		}
		if (OutDynamicCallReferencesfromAddressCheckBox.isEnabled() && OutDynamicCallReferencesfromAddressCheckBox.isSelected()) {
			this.isOutDynamicCallReferencesfromAddressCheckBoxchecked=true;
		}
		if (OutDynamicCallReferencesfromFunctionCheckBox.isEnabled() && OutDynamicCallReferencesfromFunctionCheckBox.isSelected()) {
			this.isOutDynamicCallReferencesfromFunctionCheckBoxchecked=true;
		}
		
		if (GenerateScriptCheckbox.isEnabled() && GenerateScriptCheckbox.isSelected()) {
			this.isGenerateScriptCheckboxchecked=true;
		}
		if (OutputReasonForHookGenCheckbox.isEnabled() && OutputReasonForHookGenCheckbox.isSelected()) {
			this.isOutputReasonForHookGenCheckboxchecked=true;
		}
		
		
		if (HookThisAddressCheckBox.isEnabled() && HookThisAddressCheckBox.isSelected())
		{
			this.isHookThisAddressCheckBoxchecked=true;
		}
		
		if (RangeAddressesCheckBox.isEnabled() && RangeAddressesCheckBox.isSelected()) {
			this.isRangeAddressesCheckBoxchecked=true;
			RangeAddressesNum=0;
			try {
				long tmplong=Long.parseLong(RangeAddressesNumTextField.getText());
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
		}
		
		if (RangeFunctionsCheckBox.isEnabled() && RangeFunctionsCheckBox.isSelected()) {
			this.isRangeFunctionsCheckBoxchecked=true;
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
		if (IncludeCustomTextcheckbox.isEnabled() && IncludeCustomTextcheckbox.isSelected()) {
			this.isIncludeCustomTextcheckboxchecked=true;
		}
		if (GenerateBacktraceCheckbox.isEnabled() && GenerateBacktraceCheckbox.isSelected()) {
			this.isGenerateBacktraceCheckboxchecked=true;
		}
				

		
		close();
	}
	

}

