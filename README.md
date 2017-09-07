#### Building

1. Download openfire 4.1.5 distribution (.tar.gz) from
https://igniterealtime.org/downloads/index.jsp#openfire
2. Find `openfire.jar` in `lib/` folder of the distribution file 
3. Install the .jar file as maven dependency: `mvn install:install-file -Dfile="./openfire.jar" -DgroupId="org.jivesoftware" -DartifactId=openfire -Dversion="4.1.5" -Dpackaging=jar`
4. Use `mvn` as usual