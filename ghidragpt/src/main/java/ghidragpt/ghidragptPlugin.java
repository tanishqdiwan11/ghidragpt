package ghidragpt;

import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatMessage;
import com.theokanning.openai.completion.chat.ChatMessageRole;
import com.theokanning.openai.service.OpenAiService;
import docking.Tool;
import ghidra.app.CorePluginPackage;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import java.lang.Integer;
import java.time.Duration;
import java.util.List;
import org.json.JSONObject;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

//@formatter:off
@PluginInfo(status = PluginStatus.RELEASED,
            packageName = CorePluginPackage.NAME,
            category = PluginCategoryNames.ANALYSIS,
            shortDescription = "ChatGPT Plugin for Ghidra",
            description = "Brings the power of ChatGPT to Ghidra!",
            servicesRequired = {ConsoleService.class, CodeViewerService.class})

//@formatter:on
public class ghidragptPlugin extends ProgramPlugin {
  ConsoleService cs;
  CodeViewerService cvs;
  private ghidragptComponent uiComponent;
  private String apiToken;
  private String openAiModel = "gpt-3.5-turbo";
  private int OPENAI_TIMEOUT = 120;
  private static final String GCG_IDENTIFY_STRING =
      "Describe the function with as much detail as possible and include a link to an open source version if there is one\n %s";
  private static final String GCG_VULNERABILITY_STRING =
      "Describe all vulnerabilities in this function with as much detail as possible\n %s";
  private static final String GCG_EXACT_C_CODE_STRING =
      "Provide the exact C code for this function, maintaining its functionality. Include any necessary header files or type definitions:\n %s";
  private static final String GCG_EXPLOITATION_GUIDE_STRING =
      "Provide a detailed, step-by-step guide on how to exploit any vulnerabilities in this function. Include specific techniques, potential payloads, and explain the impact of successful exploitation:\n %s";

  /**
   * Plugin constructor.
   *
   * @param tool The plugin tool that this plugin is added to.
   */
  public ghidragptPlugin(PluginTool tool) {
    super(tool);

    String pluginName = getName();
    uiComponent = new ghidragptComponent(this, pluginName);

    String topicName = this.getClass().getPackage().getName();
    String anchorName = "HelpAnchor";
    uiComponent.setHelpLocation(new HelpLocation(topicName, anchorName));
  }

  @Override
  public void init() {
    super.init();
    cs = tool.getService(ConsoleService.class);
    cvs = tool.getService(CodeViewerService.class);
    apiToken = System.getenv("OPENAI_TOKEN");
    if (apiToken != null)
      ok(String.format("Loaded OpenAI Token: %s", censorToken(apiToken)));
    ok(String.format("Default model is: %s", openAiModel));
  }

  public Boolean setToken(String token) {
    if (token == null)
      return false;

    apiToken = token;
    return true;
  }

  private static String censorToken(String token) {
    StringBuilder censoredBuilder = new StringBuilder(token.length());
    censoredBuilder.append(token.substring(0, 2));

    for (int i = 2; i < token.length(); i++) {
      censoredBuilder.append('*');
    }
    return censoredBuilder.toString();
  }

  public String getToken() { return apiToken; }

  public void setModel(String model) { openAiModel = model; }

  public void identifyFunction() {
    String result;
    DecompilerResults decResult = decompileCurrentFunc();
    if (decResult == null)
      return;

    log(String.format("Identifying the current function: %s",
                      decResult.func.getName()));
    result = askChatGPT(
        String.format(GCG_IDENTIFY_STRING, decResult.decompiledFunc));
    if (result == null)
      return;

    addComment(decResult.prog, decResult.func, result,
               "[ghidragpt] - Identify Function");
  }

  public void findVulnerabilities() {
    String result;
    DecompilerResults decResult = decompileCurrentFunc();
    if (decResult == null)
      return;

    log(String.format("Finding vulnerabilities in the current function: %s",
                      decResult.func.getName()));
    result = askChatGPT(
        String.format(GCG_VULNERABILITY_STRING, decResult.decompiledFunc));
    if (result == null)
      return;

    addComment(decResult.prog, decResult.func, result,
               "[ghidragpt] - Find Vulnerabilities");
  }

  public void provideExactCCode() {
    String result;
    DecompilerResults decResult = decompileCurrentFunc();
    if (decResult == null)
        return;

    log(String.format("Providing exact C code for the function: %s",
                      decResult.func.getName()));
    result = askChatGPT(
        String.format(GCG_EXACT_C_CODE_STRING, decResult.decompiledFunc));
    if (result == null)
        return;

    addComment(decResult.prog, decResult.func, result,
               "[ghidragpt] - Exact C Code");
  }

  public void provideExploitationGuide() {
    String result;
    DecompilerResults decResult = decompileCurrentFunc();
    if (decResult == null)
        return;

    log(String.format("Providing exploitation guide for the function: %s",
                      decResult.func.getName()));
    result = askChatGPT(
        String.format(GCG_EXPLOITATION_GUIDE_STRING, decResult.decompiledFunc));
    if (result == null)
        return;

    addComment(decResult.prog, decResult.func, result,
               "[ghidragpt] - Exploitation Guide");
  }

  public void generateReport() {
    DecompilerResults decResult = decompileCurrentFunc();
    if (decResult == null) {
        error("Failed to decompile the current function.");
        return;
    }

    Program program = decResult.prog;
    Function function = decResult.func;
    String decompiled = decResult.decompiledFunc;

    StringBuilder report = new StringBuilder();
    report.append("Function Analysis Report\n");
    report.append("========================\n\n");
    report.append("Program: ").append(program.getName()).append("\n");
    report.append("Function: ").append(function.getName()).append("\n");
    report.append("Address: ").append(function.getEntryPoint()).append("\n");
    report.append("Date: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())).append("\n\n");

    log(String.format("Generating report for function: %s", function.getName()));

    // Identify function
    log("Identifying function...");
    String identification = askChatGPT(String.format(GCG_IDENTIFY_STRING, decompiled));
    if (identification != null) {
        report.append("Identification:\n").append(identification).append("\n\n");
    } else {
        report.append("Identification: Failed to retrieve\n\n");
    }

    // Find vulnerabilities
    log("Finding vulnerabilities...");
    String vulnerabilities = askChatGPT(String.format(GCG_VULNERABILITY_STRING, decompiled));
    if (vulnerabilities != null) {
        report.append("Vulnerabilities:\n").append(vulnerabilities).append("\n\n");
    } else {
        report.append("Vulnerabilities: Failed to retrieve\n\n");
    }

    // Provide exploitation guide
    log("Generating exploitation guide...");
    String exploitationGuide = askChatGPT(String.format(GCG_EXPLOITATION_GUIDE_STRING, decompiled));
    if (exploitationGuide != null) {
        report.append("Exploitation Guide:\n").append(exploitationGuide).append("\n\n");
    } else {
        report.append("Exploitation Guide: Failed to retrieve\n\n");
    }

    // Provide exact C code
    log("Generating exact C code...");
    String exactCCode = askChatGPT(String.format(GCG_EXACT_C_CODE_STRING, decompiled));
    if (exactCCode != null) {
        report.append("Exact C Code:\n").append(exactCCode).append("\n\n");
    } else {
        report.append("Exact C Code: Failed to retrieve\n\n");
    }

    // Save the report to a file
    String fileName = program.getName() + "_" + function.getName() + "_analysis_report.txt";
    try (FileWriter writer = new FileWriter(fileName)) {
        writer.write(report.toString());
        ok("Report saved to " + fileName);
    } catch (IOException e) {
        error("Failed to save the report: " + e.getMessage());
    }
}

  private String decompileFunction(Function func) {
    FlatProgramAPI programApi = new FlatProgramAPI(currentProgram);
    FlatDecompilerAPI decompiler = new FlatDecompilerAPI(programApi);
    try {
        return decompiler.decompile(func);
    } catch (Exception e) {
        error(String.format("Failed to decompile the function: %s with the error %s", func.getName(), e));
        return "";
    }
  }

  private Boolean checkOpenAIToken() {
    if (apiToken != null)
      return true;

    if (!setToken(uiComponent.askForOpenAIToken())) {
      error("Failed to update the OpenAI API token");
      return false;
    }
    return true;
  }

  private class DecompilerResults {
    public Program prog;
    public Function func;
    public String decompiledFunc;

    public DecompilerResults(Program prog, Function func,
                             String decompiledFunc) {
      this.prog = prog;
      this.func = func;
      this.decompiledFunc = decompiledFunc;
    }
  }

  private DecompilerResults decompileCurrentFunc() {
    String decompiledFunc;

    ProgramLocation progLoc = cvs.getCurrentLocation();
    Program prog = progLoc.getProgram();
    FlatProgramAPI programApi = new FlatProgramAPI(prog);
    FlatDecompilerAPI decompiler = new FlatDecompilerAPI(programApi);
    Function func = programApi.getFunctionContaining(progLoc.getAddress());
    if (func == null) {
      error("Failed to find the current function");
      return null;
    }

    try {
      decompiledFunc = decompiler.decompile(func);
    } catch (Exception e) {
      error(String.format(
          "Failed to decompile the function: %s with the error %s",
          func.getName(), e));
      return null;
    }

    return new DecompilerResults(prog, func, decompiledFunc);
  }

  private void addComment(Program prog, Function func, String comment,
                          String commentHeader) {
    var id = prog.startTransaction("ghidragpt");
    String currentComment = func.getComment();
    if (currentComment != null) {
      currentComment =
          String.format("%s\n%s\n\n%s", commentHeader, comment, currentComment);
    } else {
      currentComment = String.format("%s\n%s", commentHeader, comment);
    }

    func.setComment(currentComment);
    prog.endTransaction(id, true);
    ok(String.format(
        "Added the ChatGPT response as a comment to the function: %s",
        func.getName()));
  }

  private String askChatGPT(String prompt) {
    String response = sendOpenAIRequest(prompt);
    if (response == null) {
      error("The ChatGPT response was empty, try again!");
      return null;
    }

    return response;
  }

  private String sendOpenAIRequest(String prompt) {
    StringBuilder response = new StringBuilder();
    if (!checkOpenAIToken())
      return null;

    OpenAiService openAIService =
        new OpenAiService(apiToken, Duration.ofSeconds(OPENAI_TIMEOUT));
    if (openAIService == null) {
      error("Failed to start the OpenAI service, try again!");
      return null;
    }

    ChatCompletionRequest chatCompletionRequest =
        ChatCompletionRequest.builder()
            .model(openAiModel)
            .temperature(0.8)
            .messages(List.of(
                new ChatMessage(
                    ChatMessageRole.SYSTEM.value(),
                    "You are an assistant helping out with reverse engineering and vulnerability research"),
                new ChatMessage(ChatMessageRole.USER.value(), prompt)))
            .build();

    try {
      StringBuilder builder = new StringBuilder();
      openAIService.createChatCompletion(chatCompletionRequest)
          .getChoices()
          .forEach(
              choice -> { builder.append(choice.getMessage().getContent()); });

      return builder.toString();
    } catch (Exception e) {
      error(String.format("Asking ChatGPT failed with the error %s", e));
      return null;
    }
  }

  public void log(String message) {
    cs.println(String.format("%s [>] %s", getName(), message));
  }

  public void error(String message) {
    cs.println(String.format("%s [-] %s", getName(), message));
  }

  public void ok(String message) {
    cs.println(String.format("%s [+] %s", getName(), message));
  }
}
