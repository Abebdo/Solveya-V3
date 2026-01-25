
import { MessageEngine } from "../internalEngines/messageEngine";
import { URLEngine } from "../internalEngines/urlEngine";

export class MockEngine {
  static async analyzeMessage(text: string) {
    console.log("MockEngine: Analyze Message");
    return MessageEngine.analyze(text);
  }

  static async analyzeURL(url: string) {
      console.log("MockEngine: Analyze URL");
      return URLEngine.analyze(url);
  }
}
