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

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;

import ghidra.util.task.TaskMonitor;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

/*
 * IMPORTANT: This does not work well.
 * In the general case, the number of functions is too large, and ChatGPT cannot process them all.
 * Ideally, a local GPT solution can be used but sufficiently powerful hardware will be needed, 
 * and it would also be good to have a model trained on very large inputs.
 * As of now, AI integration is not included in the functionality of the plugin.
 */
public class ChatGPTAPICaller {
	
	enum Errortype {
		NO_ERROR,
	    API_KEY_FILE_ERROR,
	    CANT_CONNECT,
	    UNEXPECTED_RESPONSE
	  };
	
	String url = "https://api.openai.com/v1/chat/completions";
    String apiKey = "API_KEY_PLACEHOLDER";
    String model = "gpt-3.5-turbo"; //"gpt-4o";
    String chatgpt_apikey_filepath=System.getProperty("user.home")+"/.ghidra/chatgpt_apikey.txt";
    TaskMonitor incoming_monitor;
    
    String prompt_for_many_functions1="First, disregard all previous messages as there is a new task for you. Also, clear any function name counters you were holding, set them to 0.\\n Here is the task. You will be given a list of function names, with numbers assigned to them. In the end you will be required to provide only the list of numbers corresponding to the function names that seem related to ";
    String prompt_for_many_functions2=". You will have to return only the numbers in the end (separated by commas), nothing else.\\n"
    		+ "The list of function names will start from the next message, may span across multiple messages, and will end when the string 'END_OF_LIST_OF_FUNCTIONS' is sent by me.\\n "
    		+ "For every intermediate message as the function names are being sent, only reply with the total number of function names you have ingested so far (not the names themselves), and don't say anything else. At the end, when the list of function names is complete, only output the list of  the corresponding numbers you have created. ";
    
    String prompt_for_intermediate_message1="Here are the function names for this intermediate message (which is the message at position ";
    String prompt_for_intermediate_message2="), each function name in a separate line, preceded by a number corresponding to it. Remember, do not answer just yet, only acknowlege the total number of function names you have received so far in this message, and in total for all the messages you have received from the beginning of this task. Do not send the canary string specified in the first message, at the start of the instructions.\\n```\\n";
    String finalmessage1="END_OF_LIST_OF_FUNCTIONS\\nNow, only provide the list of numbers you were instructed to create (and nothing else), separated by commas, and the numbers correspond to the function names that seem related to ";
    String finalmessage2="\\nDo not output anything else other than the list of numbers itself.\\n";
    
    ArrayList<String> pastprompts_user;
    ArrayList<String> pastprompts_assistant;
    
    public ChatGPTAPICaller(TaskMonitor incoming_monitor) {
    	this.incoming_monitor=incoming_monitor;
    	this.pastprompts_user=new ArrayList<String>();
    	this.pastprompts_assistant=new ArrayList<String>();
    	Errortype errortype;
    	errortype=this.get_api_key_from_disk();
    	if (errortype==Errortype.API_KEY_FILE_ERROR)
    	{
    		System.out.println("Error in reading chatgpt api key file");
    	}

    	
    }
    
    public String askchatGPT_multiplemessages(String category,ArrayList<String> function_names)
    {
    	String retval="";
    	String first_prompt=this.prompt_for_many_functions1+category+this.prompt_for_many_functions2;
    	
    	System.out.println(first_prompt);
    	String first_reply=askchatGPT_onemessage(first_prompt);
    	System.out.println(first_reply);
    	
    	int total_function_names=function_names.size();
    	int total_messages=1;
    	int function_names_to_be_sent_in_each_batch=300;
    	int num_of_names_included_in_this_batch=0;
    	String function_names_to_be_sent_in_this_batch="";
    	
    	//Iterate on all function names and send their names in batches
    	for (int i=0;i<total_function_names;i++)
    	{
    		if (i%20==0)
    		{
    			this.incoming_monitor.setMessage("Sending function names to ChatGPT..."+Integer.toString(i)+"/"+Integer.toString(total_function_names));
    			if (this.incoming_monitor.isCancelled()) {return "CANCELLED";} //check for cancellation by the user
    		}
    		num_of_names_included_in_this_batch++;
    		function_names_to_be_sent_in_this_batch+=i+" "+function_names.get(i)+"\\n";
    		if (num_of_names_included_in_this_batch==function_names_to_be_sent_in_each_batch || i==total_function_names-1)
    		{
    			try {
    				//sleep for a bit so that we don't hit the API too much
					Thread.sleep(200);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
    			total_messages++;
    			String intermediate_reply=askchatGPT_onemessage(this.prompt_for_intermediate_message1+total_messages+this.prompt_for_intermediate_message2+function_names_to_be_sent_in_this_batch+"\\n```");
    			System.out.println(intermediate_reply);
    			function_names_to_be_sent_in_this_batch="";
    			num_of_names_included_in_this_batch=0;
    		}
    	}
    	retval=askchatGPT_onemessage(this.finalmessage1+category+this.finalmessage2);
    	return retval;
    }
	
    //https://rollbar.com/blog/how-to-use-chatgpt-api-with-java/#
	 public String askchatGPT_onemessage(String prompt) {
	       
	       try {
	           URL obj = new URI(this.url).toURL();
	           HttpURLConnection connection = (HttpURLConnection) obj.openConnection();
	           connection.setRequestMethod("POST");
	           connection.setRequestProperty("Authorization", "Bearer " + apiKey);
	           connection.setRequestProperty("Content-Type", "application/json");

	           
	           this.pastprompts_user.add(prompt); //add the message to the past messages
	           
	           // The request body must also include the past conversation
	           String body = "{\"model\": \"" + model + "\", \"messages\": "+this.create_json_body_with_all_messages()+"}";
	           connection.setDoOutput(true);
	           OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream());
	           writer.write(body);
	           writer.flush();
	           writer.close();

	           // Response from ChatGPT
	           BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
	           String line;

	           StringBuffer response = new StringBuffer();

	           while ((line = br.readLine()) != null) {
	               response.append(line);
	           }
	           br.close();

	           // calls the method to extract the message.
	           String return_message=extractMessageFromJSONResponse(response.toString());
	           this.pastprompts_assistant.add(return_message); //add it to the list of received messages
	           return return_message;

	       } catch (IOException e) {
	           throw new RuntimeException(e);
	       } catch (URISyntaxException e)
	       {
	    	   //the URL is fixed so we won't go here
	    	   throw new RuntimeException(e);
	       }
	 	
	   }
	 
	   //Add all observed past messages
	   public String create_json_body_with_all_messages()
	   {
		   String retval="[";
		   for (int i=0;i<this.pastprompts_user.size();i++)
		   {
			   retval+="{\"role\": \"user\", \"content\": \"" + this.pastprompts_user.get(i) + "\"}";
			   if (i<this.pastprompts_assistant.size())
			   {
				   retval+=",{\"role\": \"assistant\", \"content\": \"" + this.pastprompts_assistant.get(i) + "\"},";
			   }
		   }
		   retval+="]";
		   return retval;
	   }

	   public String extractMessageFromJSONResponse(String response) {
	       int start = response.indexOf("content")+ 11;

	       int end = response.indexOf("\"", start);

	       return response.substring(start, end);

	   }
	   
	   public  Errortype get_api_key_from_disk()
	   {
		   BufferedReader reader;

			try {
				reader = new BufferedReader(new FileReader(chatgpt_apikey_filepath));
				String line = reader.readLine();
				this.apiKey=line;
				reader.close();
				return Errortype.NO_ERROR;
			} catch (IOException e) {
				return Errortype.API_KEY_FILE_ERROR;
			}
	   }

}
