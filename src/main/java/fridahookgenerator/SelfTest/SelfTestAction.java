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

package fridahookgenerator.SelfTest;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;

/*
 * The right click option that runs the self test.
 *
 * Careful: it is switched off unless the system property below is set, so it never appears to somebody who is simply using
 * the plugin. A property was chosen instead of a constant that is false, because a property does not need the extension to
 * be built again: it is enough to start Ghidra with
 *
 *     -Dfridahookgenerator.selftest=1
 *
 * or to add that to the VMARGS of the launch properties of Ghidra.
 *
 * The whole of this directory can be deleted, in which case the only thing that has to be removed from the rest of the
 * plugin is the one line of FridaHookGeneratorPlugin that adds this action, and its import.
 */
public class SelfTestAction extends ListingContextAction {

	public static final String name_of_the_property_that_enables_the_self_test="fridahookgenerator.selftest";

	private Plugin incoming_plugin;
	private SelfTestRunner.Level level;

	/*
	 * Adds the three options, one per level, to the tool. This is the only thing that the rest of the plugin has to call,
	 * so that adding a level here never means touching the plugin again.
	 */
	public static void add_the_self_test_actions_to_the_tool(PluginTool tool,Plugin plugin)
	{
		tool.addAction(new SelfTestAction(plugin,SelfTestRunner.Level.LOW));
		tool.addAction(new SelfTestAction(plugin,SelfTestRunner.Level.MEDIUM));
		tool.addAction(new SelfTestAction(plugin,SelfTestRunner.Level.FULL));
	}

	public SelfTestAction(Plugin incoming_plugin,SelfTestRunner.Level level)
	{
		super("Run the Frida Hook Generator self test ("+level+")",incoming_plugin.getName());
		this.incoming_plugin=incoming_plugin;
		this.level=level;
		setPopupMenuData(new MenuData(new String[]{"Run the Frida Hook Generator self test ("+return_the_word_for_the_level(level)+")..."},null,"Frida-Hook"));
		setDescription("Generates hooks for combinations of the options and checks whether the produced javascript makes sense. "+return_the_description_of_the_level(level));
	}

	protected static String return_the_word_for_the_level(SelfTestRunner.Level level)
	{
		if (level==SelfTestRunner.Level.LOW)
		{
			return "quick";
		}
		if (level==SelfTestRunner.Level.MEDIUM)
		{
			return "medium";
		}
		return "full";
	}

	protected static String return_the_description_of_the_level(SelfTestRunner.Level level)
	{
		if (level==SelfTestRunner.Level.LOW)
		{
			return "The quick one: the combinations that the others are built on, and a few hooks of every script. Seconds.";
		}
		if (level==SelfTestRunner.Level.MEDIUM)
		{
			return "The medium one: most of the combinations, and enough hooks of every script to be representative.";
		}
		return "The full one: every combination, including the ones that walk over every function and every symbol of the program, and every hook of every script. This can take a long time on a large program.";
	}

	/*Whether the self test is switched on at all. The action registers itself in any case, but it stays invisible*/
	public static Boolean is_the_self_test_enabled()
	{
		return Boolean.valueOf(System.getProperty(name_of_the_property_that_enables_the_self_test)!=null);
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context)
	{
		if (!is_the_self_test_enabled().booleanValue())
		{
			return false;
		}
		return context.getProgram()!=null;
	}

	@Override
	protected void actionPerformed(ListingActionContext context)
	{
		PluginTool tool=this.incoming_plugin.getTool();
		ConsoleService console_service=tool.getService(ConsoleService.class);

		SelfTestRunner runner=new SelfTestRunner(tool,context.getProgram(),this.level);
		SelfTestReport report=runner.run_everything();
		String text_of_the_report=report.return_the_whole_report();

		System.out.println(text_of_the_report);
		if (console_service!=null)
		{
			console_service.println(text_of_the_report);
		}
	}
}
