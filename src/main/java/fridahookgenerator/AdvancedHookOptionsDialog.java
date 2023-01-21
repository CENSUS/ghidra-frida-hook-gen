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
import javax.swing.JScrollPane;
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
	public Boolean isOKpressed;
	public Boolean is_invoked_from_selecting_multiple_addresses;
	
	/*Incoming References items*/
	public JCheckBox ReferencestoAddressCheckBox;
	public Boolean isReferencestoAddressCheckBoxchecked;
	public JCheckBox FunctionsReferencingAddressCheckBox;
	public Boolean isFunctionsReferencingAddressCheckBoxchecked;
	public JCheckBox ReferencestoFunctionCheckbox;
	public Boolean isReferencestoFunctionCheckboxchecked;
	public JCheckBox FunctionsReferencingFunctionCheckbox;
	public Boolean isFunctionsReferencingFunctionCheckboxchecked;
	public JComboBox<String> InFunctionReferenceDepthcomboBox;
	
	/*Outgoing References items*/
	public JCheckBox OutReferencesfromFunctionCheckBox;
	public Boolean isOutReferencesfromFunctionCheckBoxchecked;
	public JComboBox<String> OutFunctionReferenceDepthcomboBox;
	public JCheckBox OutReferencesfromAddressCheckBox;
	public Boolean isOutReferencesfromAddressCheckBoxchecked;
	public JCheckBox OutDynamicCallReferencesfromFunctionCheckBox;
	public Boolean isOutDynamicCallReferencesfromFunctionCheckBoxchecked;
	public JCheckBox OutDynamicCallReferencesfromAddressCheckBox;
	public Boolean isOutDynamicCallReferencesfromAddressCheckBoxchecked;
	
	/*Range items*/
	public JCheckBox HookThisAddressCheckBox;
	public Boolean isHookThisAddressCheckBoxchecked;
	public JCheckBox RangeAddressesCheckBox;
	public Boolean isRangeAddressesCheckBoxchecked;
	public JCheckBox RangeFunctionsCheckBox;
	public Boolean isRangeFunctionsCheckBoxchecked;
	public GLabel RangeAddressesNumLabel;
	public JTextField RangeAddressesNumTextField;
	public int RangeAddressesNum;
	public GLabel RangeFunctionsNumLabel;
	public JTextField RangeFunctionsNumTextField;
	public int RangeFunctionsNum;
	public ButtonGroup RangeAddressesButtonGroup;
	public GRadioButton RangeAddressesRadioButtonAddr;
	public GRadioButton RangeAddressesRadioButtonInstr;
	public GRadioButton RangeAddressesRadioButtonFun;
	public ButtonGroup RangeFunctionsButtonGroup;
	public GRadioButton RangeFunctionsRadioButtonAddr;
	public GRadioButton RangeFunctionsRadioButtonInstr;
	public GRadioButton RangeFunctionsRadioButtonFun;
	public GRadioButton RangeFunctionsRadioButtonFunBackwards;

	
	/*Output items*/
	public JCheckBox OutputReasonForHookGenCheckbox;
	public Boolean isOutputReasonForHookGenCheckboxchecked;
	public JComboBox<String> ReasonForHookGenAmountcomboBox;
	public JCheckBox GenerateScriptCheckbox;
	public Boolean isGenerateScriptCheckboxchecked;
	public JComboBox<String> TypeofScriptGenerationcomboBox;
	public JCheckBox CustomFunInterceptorHookOutputCheckbox;
	public Boolean isCustomFunInterceptorHookOutputCheckboxchecked;
	public JComboBox<String> CustomFunInterceptorHookOutputcomboBox;
	public JCheckBox DoNotIncludeFunParamscheckbox;
	public Boolean isDoNotIncludeFunParamscheckboxchecked;
	public JCheckBox GenerateBacktraceCheckbox;
	public Boolean isGenerateBacktraceCheckboxchecked;
	public JComboBox<String> GenerateBacktracecomboBox;
	public JCheckBox GenerateNormalAddressHooksForFunctionBeginningscheckbox;
	public Boolean isGenerateNormalAddressHooksForFunctionBeginningscheckboxchecked;

	/*Multi-Hook management items*/
	public JCheckBox FunctionRegexCheckBox;
	public Boolean isFunctionRegexCheckBoxchecked;
	public JTextField FunctionRegexTextField;
	public JCheckBox HookExportsCheckBox;
	public Boolean isHookExportsCheckBoxchecked;
	public JCheckBox CreateDataStructuresToLinkAddressesAndFunctionNamescheckbox;
	public Boolean isCreateDataStructuresToLinkAddressesAndFunctionNamescheckboxchecked;
	public JCheckBox IncludeCustomTextcheckbox;
	public Boolean isIncludeCustomTextcheckboxchecked;
	public JTextField IncludeCustomTextTextField;
	public JCheckBox IncludeInterceptorTryCatchcheckbox;
	public Boolean isIncludeInterceptorTryCatchcheckboxchecked;
	public JCheckBox DoNotHookThunkFunctionscheckbox;
	public Boolean isDoNotHookThunkFunctionscheckboxchecked;
	public JCheckBox DoNotHookExternalFunctionscheckbox;
	public Boolean isDoNotHookExternalFunctionscheckboxchecked;
	
	private Program current_program;
	private Address addr;

	public AdvancedHookOptionsDialog(PluginTool tool, Program current_program)
	{
		/*Constructor that is used for API calling*/
		this("API-generated Advanced Hook Options Dialog", tool, current_program,true);
	}
	
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
		this.isHookExportsCheckBoxchecked=false;
		this.isGenerateBacktraceCheckboxchecked=false;
		this.isIncludeCustomTextcheckboxchecked=false;
		this.isOutDynamicCallReferencesfromFunctionCheckBoxchecked=false;
		this.isOutDynamicCallReferencesfromAddressCheckBoxchecked=false;
		this.isIncludeInterceptorTryCatchcheckboxchecked=false;
		this.isDoNotHookThunkFunctionscheckboxchecked=false;
		this.isDoNotHookExternalFunctionscheckboxchecked=false;
		this.isCreateDataStructuresToLinkAddressesAndFunctionNamescheckboxchecked=false;
		this.isGenerateNormalAddressHooksForFunctionBeginningscheckboxchecked=false;
		
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
		
		GenerateNormalAddressHooksForFunctionBeginningscheckbox= new GCheckBox("For function beginnings, do not use OnEnter()/OnLeave() methods at all, but generate hooks treating them as normal addresses");
		GenerateNormalAddressHooksForFunctionBeginningscheckbox.setToolTipText(
				"If an adress is at the start of a function, then normally onEnter()/onLeave() methods are created in its hook. This option forces the address to be treated as any other address, without onEnter()/onLeave() methods. This will also cause the execution to not follow any code paths that assume that the address is at the start of a function.");
		
		
		FunctionRegexCheckBox=new GCheckBox("Generate hooks for functions whose name matches the following (case insensitive) regular expression:");
		FunctionRegexCheckBox.setToolTipText("In the case where the function names are known, similarly named functions may fall under the same functional block, and hooking all of them can be useful");
		FunctionRegexTextField=new JTextField(10);
		
		HookExportsCheckBox=new GCheckBox("Generate hooks for all exported symbols");
		HookExportsCheckBox.setToolTipText("Generate hooks for all exported symbols which can be entry points. This is useful when you want to identify from which point a shared library is entered.");
		
		CreateDataStructuresToLinkAddressesAndFunctionNamescheckbox=new GCheckBox("Create and initialize data structures that associate the hooked addresses with function names, accessible from javascript");
		CreateDataStructuresToLinkAddressesAndFunctionNamescheckbox.setToolTipText("CrGenerateNormalAddressHooksForFunctionBeginningscheckboxeate and initialize the relevant data structures, as it may be useful to be able to fetch the current function name (as visible in Ghidra) from the current address in javascript (accessible through \"this.context.pc\")");
		
		IncludeCustomTextcheckbox=new GCheckBox("Add the following javascript code in every hook generated:");
		IncludeCustomTextcheckbox.setToolTipText("Adds javascript code in every hook, at the start (not present in function hook if onEnter() is removed)");
		IncludeCustomTextTextField=new JTextField(30);
		
		IncludeInterceptorTryCatchcheckbox=new GCheckBox("Add try/catch blocks for Interceptor calls in order to not stop in case of error");
		IncludeInterceptorTryCatchcheckbox.setToolTipText("If Frida fails to register an Interceptor, it stops and does not register any other hooks coming after the one that errors. By using a try/catch scheme, this can be bypassed. Warning: You might want to stop on error, use this option with caution.");
		
		DoNotHookThunkFunctionscheckbox=new GCheckBox("Do not hook Thunk Functions even if they fall into the range of the addresses to be hooked");
		DoNotHookThunkFunctionscheckbox.setToolTipText("In case of multiple function calls, hooking Thunk functions may add too many or failed hooks, or even block the hooking of a larger function if the thunk code is close to its beginning");
		
		DoNotHookExternalFunctionscheckbox=new GCheckBox("Do not hook External Functions even if they fall into the range of the addresses to be hooked");
		DoNotHookExternalFunctionscheckbox.setToolTipText("In case of multiple function calls, hooking External functions may add too many or failed hooks, or even block the hooking of a larger function if the external function code is close to its beginning");
		

		
		JPanel mainPanel = new JPanel(new VerticalLayout(30));
		//mainPanel.setPreferredSize(new Dimension(980,650));  //if not enough, make larger
		JPanel referencesPanel = new JPanel(new VerticalLayout(4));
		JPanel referencessubPanel = new JPanel(new HorizontalLayout(4));
		JPanel outreferencesPanel = new JPanel(new VerticalLayout(4));
		JPanel outreferencessubPanel = new JPanel(new HorizontalLayout(4));
		JPanel rangePanel = new JPanel(new VerticalLayout(4));
		JPanel rangeSubPanel1 = new JPanel(new HorizontalLayout(4));
		JPanel rangeSubPanel2 = new JPanel(new HorizontalLayout(4));
		JPanel outputPanel = new JPanel(new VerticalLayout(4));
		JPanel outputSubPanel1 = new JPanel(new HorizontalLayout(4));
		JPanel outputSubPanel2 = new JPanel(new HorizontalLayout(4));
		JPanel outputSubPanel3 = new JPanel(new HorizontalLayout(4));
		JPanel outputSubPanel4 = new JPanel(new HorizontalLayout(4));
		JPanel multihookPanel = new JPanel(new VerticalLayout(4));
		JPanel multihookSubPanel1 = new JPanel(new HorizontalLayout(4));
		JPanel multihookSubPanel2 = new JPanel(new HorizontalLayout(4));

		
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
		
		TitledBorder multihookborder =
				BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Management Options for Multiple Hooks");
		multihookPanel.setBorder(multihookborder);
		

		mainPanel.add(referencesPanel);
		mainPanel.add(outreferencesPanel);
		mainPanel.add(rangePanel);
		mainPanel.add(outputPanel);
		mainPanel.add(multihookPanel);

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

		
		outputSubPanel1.add(OutputReasonForHookGenCheckbox);
		outputSubPanel1.add(ReasonForHookGenAmountcomboBox);
		outputSubPanel2.add(CustomFunInterceptorHookOutputCheckbox);
		outputSubPanel2.add(CustomFunInterceptorHookOutputcomboBox);
		outputSubPanel3.add(GenerateBacktraceCheckbox);
		outputSubPanel3.add(GenerateBacktracecomboBox);
		outputSubPanel4.add(GenerateScriptCheckbox);
		outputSubPanel4.add(TypeofScriptGenerationcomboBox);
		outputPanel.add(outputSubPanel1,BorderLayout.NORTH);
		outputPanel.add(outputSubPanel2,BorderLayout.NORTH);
		outputPanel.add(outputSubPanel3,BorderLayout.NORTH);
		outputPanel.add(DoNotIncludeFunParamscheckbox,BorderLayout.NORTH);
		outputPanel.add(GenerateNormalAddressHooksForFunctionBeginningscheckbox,BorderLayout.NORTH);
		outputPanel.add(outputSubPanel4,BorderLayout.NORTH);
		
		
		if (!is_invoked_from_selecting_multiple_addresses)
		{
			multihookSubPanel1.add(FunctionRegexCheckBox);
			multihookSubPanel1.add(FunctionRegexTextField);
			multihookPanel.add(multihookSubPanel1);
			multihookPanel.add(HookExportsCheckBox);
		}
		
		multihookPanel.add(CreateDataStructuresToLinkAddressesAndFunctionNamescheckbox);
		multihookSubPanel2.add(IncludeCustomTextcheckbox);
		multihookSubPanel2.add(IncludeCustomTextTextField);
		multihookPanel.add(multihookSubPanel2);
		multihookPanel.add(IncludeInterceptorTryCatchcheckbox,BorderLayout.NORTH);
		multihookPanel.add(DoNotHookThunkFunctionscheckbox,BorderLayout.NORTH);
		multihookPanel.add(DoNotHookExternalFunctionscheckbox,BorderLayout.NORTH);
		
		mainPanel.setPreferredSize(mainPanel.getPreferredSize());
		mainPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		
		
		JScrollPane scroller = new JScrollPane(mainPanel);
		JPanel PaneltoReturn = new JPanel();
		PaneltoReturn.setLayout(new BorderLayout());
		PaneltoReturn.add(scroller,BorderLayout.CENTER);
		
		return PaneltoReturn;
	}


	public void fetch_advanced_hook_options(Address address, Program prog) {
		fetch_advanced_hook_options(address, prog, tool.getActiveWindow());
	}
	
	
	public void fetch_advanced_hook_options(Address address, Program targetProgram, Component centeredOverComponent) {
		initDialogForAdvancedHookOptions(targetProgram, address);
		tool.showDialog(this, centeredOverComponent);
	}
	
		
	
	protected void initDialogForAdvancedHookOptions(Program p, Address address) {

		this.addr = address;
		this.current_program = p;

		if (!is_invoked_from_selecting_multiple_addresses && address!=null)
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
		GenerateNormalAddressHooksForFunctionBeginningscheckbox.setEnabled(true);
		IncludeCustomTextcheckbox.setEnabled(true);
		FunctionRegexCheckBox.setEnabled(true);
		HookExportsCheckBox.setEnabled(true);
		GenerateBacktraceCheckbox.setEnabled(true);
		CreateDataStructuresToLinkAddressesAndFunctionNamescheckbox.setEnabled(true);
		IncludeCustomTextcheckbox.setEnabled(true);
		IncludeInterceptorTryCatchcheckbox.setEnabled(true);
		DoNotHookThunkFunctionscheckbox.setEnabled(true);
		DoNotHookExternalFunctionscheckbox.setEnabled(true);
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
		if (HookExportsCheckBox.isEnabled() && HookExportsCheckBox.isSelected())
		{
			this.isHookExportsCheckBoxchecked=true;
		}
		if (CustomFunInterceptorHookOutputCheckbox.isEnabled() && CustomFunInterceptorHookOutputCheckbox.isSelected()) {
			this.isCustomFunInterceptorHookOutputCheckboxchecked=true;
		}
		if (DoNotIncludeFunParamscheckbox.isEnabled() && DoNotIncludeFunParamscheckbox.isSelected()) {
			this.isDoNotIncludeFunParamscheckboxchecked=true;
		}
		if (GenerateNormalAddressHooksForFunctionBeginningscheckbox.isEnabled() && GenerateNormalAddressHooksForFunctionBeginningscheckbox.isSelected())
		{
			this.isGenerateNormalAddressHooksForFunctionBeginningscheckboxchecked=true;
		}	
		if (CreateDataStructuresToLinkAddressesAndFunctionNamescheckbox.isEnabled() && CreateDataStructuresToLinkAddressesAndFunctionNamescheckbox.isSelected()) {
			this.isCreateDataStructuresToLinkAddressesAndFunctionNamescheckboxchecked=true;
		}
		if (IncludeCustomTextcheckbox.isEnabled() && IncludeCustomTextcheckbox.isSelected()) {
			this.isIncludeCustomTextcheckboxchecked=true;
		}
		if (IncludeInterceptorTryCatchcheckbox.isEnabled() && IncludeInterceptorTryCatchcheckbox.isSelected())
		{
			this.isIncludeInterceptorTryCatchcheckboxchecked=true;
		}
		if (DoNotHookThunkFunctionscheckbox.isEnabled() && DoNotHookThunkFunctionscheckbox.isSelected())
		{
			this.isDoNotHookThunkFunctionscheckboxchecked=true;
		}
		if (DoNotHookExternalFunctionscheckbox.isEnabled() && DoNotHookExternalFunctionscheckbox.isSelected())
		{
			this.isDoNotHookExternalFunctionscheckboxchecked=true;
		}

		if (GenerateBacktraceCheckbox.isEnabled() && GenerateBacktraceCheckbox.isSelected()) {
			this.isGenerateBacktraceCheckboxchecked=true;
		}
				

		
		close();
	}
	

}

