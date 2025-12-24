while read line; do
  echo "$line" | base64 --decode >> arguments.txt
  echo "" >> arguments.txt
done < encoded_arguments.txt