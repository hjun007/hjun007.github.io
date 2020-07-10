# 替换$1中的相对路径，_posts中的文件读取/images中的图片
# 将替换后的$1放到_posts中
path=$1
echo "path: "$path
file=$(basename $path)
# windows不支持toc
#md-toc --insert $file
echo "generate md-toc success!"
# sed 's/原字符串/替换的字符串/g'
# s后面的字符作为分隔符
sed 's#../images#/images#g' $file >> ../_posts/$file
echo "generate web blog file success!"