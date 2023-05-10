package com.mycompany.app;

import com.google.cloud.pubsub.v1.TopicAdminClient;
import com.google.pubsub.v1.ProjectName;
import com.google.pubsub.v1.Topic;
import java.io.IOException;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main(String... args) throws Exception {
        String projectId = "sijunliu-dca-test";
    
        listTopicsExample(projectId);
      }
    
    public static void listTopicsExample(String projectId) throws IOException {
        try (TopicAdminClient topicAdminClient = TopicAdminClient.create()) {
            ProjectName projectName = ProjectName.of(projectId);
            for (Topic topic : topicAdminClient.listTopics(projectName).iterateAll()) {
            System.out.println(topic.getName());
            }
            System.out.println("Listed all topics.");
        }
    }
}
