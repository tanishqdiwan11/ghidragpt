package ghidragpt;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.Tool;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.tool.ToolConstants;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.AskDialog;
import ghidra.framework.plugintool.*;
import ghidra.util.Msg;
import java.awt.BorderLayout;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.lang.Integer;
import java.lang.Thread;
import javax.swing.*;
import resources.Icons;

public class ghidragptComponent extends ComponentProvider {

  private JPanel panel;
  private DockingAction action;
  private ghidragptPlugin gcgplugin;
  static final String FUNCTION_ID_NAME = "ghidragpt";

  public ghidragptComponent(Plugin plugin, String owner) {
    super(plugin.getTool(), owner, owner);
    gcgplugin = (ghidragptPlugin)plugin;
    createActions();
  }

  public String askForOpenAIToken() {
    AskDialog<String> dialog =
        new AskDialog<>("OpenAI API token not configured!",
                        "Enter OpenAI API Token:", AskDialog.STRING, "");
    if (dialog.isCanceled()) {
      return null;
    }
    return dialog.getValueAsString();
  }

  private void createActions() {
    // Identify function
    action = new DockingAction("GCGIdentifyFunction", getName()) {
      @Override
      public void actionPerformed(ActionContext context) {
        new Thread(() -> { gcgplugin.identifyFunction(); }).start();
      }
    };
    action.setEnabled(true);
    action.setDescription("Identify the function with the help of ChatGPT");
    action.setMenuBarData(new MenuData(new String[] {
        ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, "Identify Function"}));
    action.setKeyBindingData(new KeyBindingData(
        KeyEvent.VK_I, InputEvent.SHIFT_DOWN_MASK | InputEvent.ALT_DOWN_MASK |
                           InputEvent.CTRL_DOWN_MASK));
    dockingTool.addAction(action);

    // Find vulnerabilities
    action = new DockingAction("GCGFindVulnerabilities", getName()) {
      @Override
      public void actionPerformed(ActionContext context) {
        new Thread(() -> { gcgplugin.findVulnerabilities(); }).start();
      }
    };

    action.setEnabled(true);
    action.setDescription(
        "Find vulnerabilities in the function with the help of ChatGPT");
    action.setMenuBarData(new MenuData(new String[] {
        ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, "Find Vulnerabilities"}));
    action.setKeyBindingData(new KeyBindingData(
        KeyEvent.VK_V, InputEvent.SHIFT_DOWN_MASK | InputEvent.ALT_DOWN_MASK |
                           InputEvent.CTRL_DOWN_MASK));
    dockingTool.addAction(action);

    // Provide Exact C Code
    action = new DockingAction("GCGProvideExactCCode", getName()) {
        @Override
        public void actionPerformed(ActionContext context) {
            new Thread(() -> { gcgplugin.provideExactCCode(); }).start();
        }
    };

    action.setEnabled(true);
    action.setDescription("Provide exact C code for the function with the help of ChatGPT");
    action.setMenuBarData(new MenuData(new String[] {
        ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, "Provide Exact C Code"}));
    action.setKeyBindingData(new KeyBindingData(
        KeyEvent.VK_C, InputEvent.SHIFT_DOWN_MASK | InputEvent.ALT_DOWN_MASK |
                           InputEvent.CTRL_DOWN_MASK));
    dockingTool.addAction(action);

    // Provide Exploitation Guide
    action = new DockingAction("GCGProvideExploitationGuide", getName()) {
        @Override
        public void actionPerformed(ActionContext context) {
            new Thread(() -> { gcgplugin.provideExploitationGuide(); }).start();
        }
    };

    action.setEnabled(true);
    action.setDescription("Provide an exploitation guide for the function vulnerabilities with the help of ChatGPT");
    action.setMenuBarData(new MenuData(new String[] {
        ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, "Provide Exploitation Guide"}));
    action.setKeyBindingData(new KeyBindingData(
        KeyEvent.VK_E, InputEvent.SHIFT_DOWN_MASK | InputEvent.ALT_DOWN_MASK |
                           InputEvent.CTRL_DOWN_MASK));
    dockingTool.addAction(action);

    // Generate Report
    action = new DockingAction("GCGGenerateReport", getName()) {
        @Override
        public void actionPerformed(ActionContext context) {
            new Thread(() -> { gcgplugin.generateReport(); }).start();
        }
    };

    action.setEnabled(true);
    action.setDescription("Generate a comprehensive report of the current function analysis");
    action.setMenuBarData(new MenuData(new String[] {
        ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, "Generate Function Analysis Report"}));
    action.setKeyBindingData(new KeyBindingData(
        KeyEvent.VK_R, InputEvent.SHIFT_DOWN_MASK | InputEvent.ALT_DOWN_MASK |
                            InputEvent.CTRL_DOWN_MASK));
    dockingTool.addAction(action);

    // Update OpenAI Token
    action = new DockingAction("GCGUpdateOpenAIToken", getName()) {
      @Override
      public void actionPerformed(ActionContext context) {
        if (gcgplugin.setToken(askForOpenAIToken())) {
          gcgplugin.ok("Updated the current OpenAI API Token");
        }
      }
    };

    action.setEnabled(true);
    action.setDescription("Update the current OpenAI API Token");
    action.setMenuBarData(
        new MenuData(new String[] {ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME,
                                   "Settings", "Update OpenAI Token"}));
    dockingTool.addAction(action);

    // Update the Model used
    String[] models = {"gpt-4", "gpt-4-0613", "gpt-4-32k", "gpt-3.5-turbo",
                       "gpt-3.5-turbo-16k"};

    for (String model : models) {
      DockingAction modelAction =
          new DockingAction("Model - " + model, "Model Category") {
            @Override
            public void actionPerformed(ActionContext context) {
              gcgplugin.setModel(model);
              gcgplugin.ok(String.format("Updated model to %s", model));
            }
          };

      modelAction.setMenuBarData(new MenuData(new String[] {
          ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, "Model", model}));

      dockingTool.addAction(modelAction);
    }
  }

  @Override
  public JComponent getComponent() {
    return panel;
  }
}
