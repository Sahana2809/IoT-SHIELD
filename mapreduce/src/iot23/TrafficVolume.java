package iot23;

import java.io.IOException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.Mapper;
import org.apache.hadoop.mapreduce.Reducer;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;

/**
 * Analysis 5: total bytes transferred (orig_bytes + resp_bytes), broken down
 * by protocol and by label. Keys are prefixed PROTO: / LABEL:.
 */
public class TrafficVolume {

    public static class VolumeMapper extends Mapper<LongWritable, Text, Text, LongWritable> {
        @Override
        protected void map(LongWritable key, Text value, Context context)
                throws IOException, InterruptedException {
            IotRecord rec = IotRecord.parse(value.toString());
            if (rec == null) {
                return;
            }
            long bytes = rec.totalBytes();
            LongWritable bytesOut = new LongWritable(bytes);
            context.write(new Text("PROTO:" + rec.get(IotRecord.PROTO)), bytesOut);
            context.write(new Text("LABEL:" + rec.get(IotRecord.LABEL)), bytesOut);
        }
    }

    public static class SumReducer extends Reducer<Text, LongWritable, Text, LongWritable> {
        @Override
        protected void reduce(Text key, Iterable<LongWritable> values, Context context)
                throws IOException, InterruptedException {
            long sum = 0;
            for (LongWritable v : values) {
                sum += v.get();
            }
            context.write(key, new LongWritable(sum));
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("Usage: TrafficVolume <input> <output>");
            System.exit(2);
        }
        Configuration conf = new Configuration();
        Job job = Job.getInstance(conf, "IoT-23 Traffic Volume");
        job.setJarByClass(TrafficVolume.class);
        job.setMapperClass(VolumeMapper.class);
        job.setCombinerClass(SumReducer.class);
        job.setReducerClass(SumReducer.class);
        job.setOutputKeyClass(Text.class);
        job.setOutputValueClass(LongWritable.class);
        FileInputFormat.addInputPath(job, new Path(args[0]));
        FileOutputFormat.setOutputPath(job, new Path(args[1]));
        System.exit(job.waitForCompletion(true) ? 0 : 1);
    }
}
