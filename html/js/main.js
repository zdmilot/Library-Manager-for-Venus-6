
		// main.js v1.0 

		var edge = require('edge-js');
		var gui = require('nw.gui');
		var win = gui.Window.get();
		var path = require('path');
		var spawn = require('child_process').spawn; 

		/// Default VENUS executables. 
        var HxRun = "HxRun.exe";
		var HxMethodEditor = "HxMetEd.exe";
		var HxLiquidEditor = "HxCoreLiquidEditor.exe";
		var HxLabwareEditor = "HxLabwrEd.exe";
		var HxHSLEditor = "HxHSLMetEd.exe";
		var HxConfigEditor = "Hamilton.HxConfigEditor.exe";
		var HxVersion = "HxVersion.exe";

		//Default VENUS folders. These variables are updated on startup by the function GetVENUSPathsFromRegistry.
		var HxFolder_LogFiles = "C:\\Program Files (x86)\\HAMILTON\\LogFiles";
		var HxFolder_Methods = "C:\\Program Files (x86)\\HAMILTON\\Methods";
		var HxFolder_Bin = "C:\\Program Files (x86)\\HAMILTON\\Bin"

		const fs = require('fs');
		const sizeOf = require('image-size')
		const os = require("os");
    
        // Diskdb init
		var db = require('diskdb');
		

		var db_links = db.connect('db', ['links']);
		var db_groups = db.connect('db', ['groups']);
		var db_settings = db.connect('db', ['settings']);
		var db_tree = db.connect('db', ['tree']); // contains the tree of group ids and method ids

		var isUserAdmin = true;

		var bool_treeChanged = false; //tracks if the tree of groups/methods has been edited to re-create groups when coming back to Home screen from Settings screen.

		var linksDirectoryPath = "C:\\Program Files (x86)\\Hamilton\\Library";

		var int_maxRecent = 10;

		var functionProtection = 0;
		var internalLogon = 0;
		var username="";
		var loginAttempts = 0
		var accessRights = 0; 
		// 0= Lab service / Administrator
		// 1= Lab Programmer
		// 2= Lab Operator 2
		// 3= Lab Operator
		// 4= No access / Lab Remote service 

		var EnumAccessRights = ["Administrator" , "Lab Programmer", "Lab Operator 2" , "Lab Operator" , "No access"];

		var bool_isHamUserChangeClick = false;
	
		var click_counter = 0;
		
		//**********************************************************************

// *******  Executor DLL declarations *************

var LogOnDialog = edge.func({
    assemblyFile: 'MethodManagerHelper.dll',
    typeName: 'MethodManagerHelper.Class1',
    methodName: 'LogOnDialog'
    //Use with VENUS internal log on only
});
var LogOn = edge.func({
    assemblyFile: 'MethodManagerHelper.dll',
    typeName: 'MethodManagerHelper.Class1',
    methodName: 'LogOn'
    //Use with VENUS internal log on only
    //input "username,password"
});
var LogOff = edge.func({
    assemblyFile: 'MethodManagerHelper.dll',
    typeName: 'MethodManagerHelper.Class1',
    methodName: 'LogOff'
    //Use with VENUS internal log on only
});
var GetFunctionProtection = edge.func({
    assemblyFile: 'MethodManagerHelper.dll',
    typeName: 'MethodManagerHelper.Class1',
    methodName: 'GetFunctionProtection'
    //returns int . 1=Function Protection enabled, 0=disabled
});

var GetCurrentAccessRightOS = edge.func({
    assemblyFile: 'MethodManagerHelper.dll',
    typeName: 'MethodManagerHelper.Class1',
    methodName: 'GetCurrentAccessRightOS'
    //Use with VENUS internal log on only
    //return 
// 0= Lab service / Administrator
// 1= Lab Programmer
// 2= Lab Operator 2
// 3= Lab Operator
// 4= No access / Lab Remote service 
});
var GetCurrentUsernameOS = edge.func({
    assemblyFile: 'MethodManagerHelper.dll',
    typeName: 'MethodManagerHelper.Class1',
    methodName: 'GetCurrentUsernameOS'
    //Use with VENUS internal log on only
    //return 0=No user logged on, 1=Operator, 2=Operator2, 4=Service, 8=Programmer
});
var GetUseInternalLogOn = edge.func({
    assemblyFile: 'MethodManagerHelper.dll',
    typeName: 'MethodManagerHelper.Class1',
    methodName: 'GetUseInternalLogOn'
    //Use with VENUS internal log on only
    //return 1=Uses Hamilton Authentication , 0= Windows Auth.
});
var GetSimulation = edge.func({
    assemblyFile: 'MethodManagerHelper.dll',
    typeName: 'MethodManagerHelper.Class1',
    methodName: 'GetSimulation'
    //return 1=Simulation on (at least in one instrument or the general setting) , 0= simulation off for all instruments and general sim setting
});
var SetSimulation = edge.func({
    assemblyFile: 'MethodManagerHelper.dll',
    typeName: 'MethodManagerHelper.Class1',
    methodName: 'SetSimulation'
    //sets simulation for all instrument classes installed and the general sim setting
    //input string parameter "on" or "off"
});
var GetVENUSPathsFromRegistry = edge.func({
    assemblyFile: 'MethodManagerHelper.dll',
    typeName: 'MethodManagerHelper.Class1',
    methodName: 'GetVENUSPathsFromRegistry'
    //Gets all the default VENUS paths as a json string
    // bin-folder, cfg-folder, lib-folder, log-folder, lbw-folder, sys-folder,met-folder
});
var DetachDatabase = edge.func({
    assemblyFile: 'MethodManagerHelper.dll',
    typeName: 'MethodManagerHelper.Class1',
    methodName: 'DetachDatabase'
    //Detach the given database name
	//input :  "HamiltonVectorDb_<run_id>"
    //return :  -1 if error, 0 no error
});
	



        //**********************************************************************
        //******  EVENTS *******************************************************
        //**********************************************************************
        //Window close.   Ensure to close any background running nw.exe
		win.on('close', function () {
			if(functionProtection==1 && internalLogon==1){
				LogOff("", function(error, result) {});
			}
			gui.App.closeAllWindows();
			win.close(true);
		});

        //Window resize
		$(window).resize(function () {
			waitForFinalEvent(function () {
				fitNavBarItems();
				fitMainDivHeight();
				fitSettingsDivHeight() 
			}, 150, "");
		});

        //Window load
		$(window).load(function () {
			waitForFinalEvent(function () {
				// fitNavBarItems();
				// fitMainDivHeight();
				
				// createGroups();
				scanLinksDirectory();
				$.when(initVENUSData()).then(createGroups()).then(
					setTimeout(function(){historyCleanup()},100)
				).then(fitSettingsDivHeight());
			}, 150, "");
        });

		$(document).on("click",".brand-logo", function(){
			click_counter++;
			if(click_counter<5){
				$(".click-count").text(click_counter);
			}
			if(click_counter==5){
				$(".click-count").text("");
				// $(".click-count").text("").append('<i class="fa fa-grin-alt mr-2 ml-2"></i>');
			}
			if(click_counter>=5){ 
				$("#magic-pass").val('');
				$("#passModal").modal();
			}
		})
		
		$(document).on("click", "#passModal .btn-primary", function(e){
			var pass_found = false;
			var pass = $("#magic-pass").val().toLowerCase();
			
			if(pass.includes("barrel roll")){
				pass_found=true;
				doBarrelRoll();
			}
			if(pass.includes("icons")){
				pass_found=true;
				$("#passModal .modal-title").text("Bonus icons unlocked!");
				$(".icons-list .d-none").removeClass("d-none");
			}
			if(pass =="help"){
				pass_found=true;
				$("#passModal .modal-title").text("alvaro.cuevas@hamiltoncompany.com");
			}
			if(pass =="shake"){
				pass_found=true;
				$.when($("#passModal").modal("hide")).then($(".link-icon,.nav-item").effect("shake"));
			}
			if(pass =="trippy"){
				pass_found=true;
				$("#passModal").modal("hide");
				$("body").get(0).style.setProperty("--medium", "#ff00aa"); 
				$("body").get(0).style.setProperty("--medium2","#ff000d");
				$("body").get(0).style.setProperty("--navbar-font-over","white");
				$("body").get(0).style.setProperty("--navbar-font","#ff9900");
				$("body").get(0).style.setProperty("--dark1","#0004ff");
				$("body").get(0).style.setProperty("--body-background","#fbff00");
				$("body").get(0).style.setProperty("--method-background","rgb(119, 252, 190)");
				$("body").get(0).style.setProperty("--solid-button-background","#3700ff");
				$("body").get(0).style.setProperty("--solid-button-over","#2049ff");
				$("body").get(0).style.setProperty("--solid-button-font","rgb(245, 166, 252)");
			}
			if(pass =="illumina"){
				pass_found=true;
				$("#passModal").modal("hide");
				// $(".brand-logo").attr("src", "img/Illumina_logo.png")
				$("body").get(0).style.setProperty("--medium-rgb","252, 203, 67"); 
				$("body").get(0).style.setProperty("--medium","#fccb43"); 
				$("body").get(0).style.setProperty("--medium2","#f5b402");
				$("body").get(0).style.setProperty("--navbar-font-over","white");
				$("body").get(0).style.setProperty("--navbar-font","#ffeb7c");
				$("body").get(0).style.setProperty("--dark1","#d49d05");
				$("body").get(0).style.setProperty("--body-background","#e7ecef");
				$("body").get(0).style.setProperty("--method-background","white");
				$("body").get(0).style.setProperty("--solid-button-background","#ffc400");
				$("body").get(0).style.setProperty("--solid-button-over","#ffd755");
				$("body").get(0).style.setProperty("--solid-button-font","white");
			}

			if(!pass_found){
				$("#passModal .modal-title").text("No tricks for that password");
					e.preventDefault();
					e.stopPropagation();
			}
		});

		$(document).on("change keydown keyup", "#magic-pass",function(e){
			if(e.type=="keydown" && e.keyCode==13){ //pressed enter
				$("#passModal .btn-primary").trigger("click");
			}
		});
        
        //Method groups -  navigation bar events
		$(document).on("click", ".navbar-custom .nav-item:not('.dropdown'), .navbar-custom .dropdown-navitem", function () { 
            
            //change active nav item
			$(".navbar-custom .nav-item, .navbar-custom .dropdown-navitem").removeClass("active");
            $(this).addClass("active");
            
			//display links group
			var group_id = $(this).attr('data-group-id');
			$('.group-container').addClass('d-none');

			
			if(group_id == "gAll"){
				//If this is ALL , display all custom group containers that are displayed in the navbar.
				$(".navbarLeft>.custom-group:not('.d-none'), hidden-nav-items>.custom-group:not('.d-none')").each(function(){
					var g = $(this).attr("data-group-id");
					$('.group-container[data-group-id="' + g + '"').removeClass('d-none');
				  });
			}else{
				$('.group-container[data-group-id="' + group_id + '"').removeClass('d-none');
			}

			//if "last tab opened" setting is checked, save this group id as the "startup-tab" in settings.json
			if($("#settings-startupLast").prop("checked")){
				saveSetting("startup-tab", group_id);
			}
			
			
        });
        
        //Open detail modal when clicking a card body
		$(document).on("click", ".link-detail-trigger", function () {
			var id = $(this).attr("data-id") || $(this).closest(".link-card-container").attr("data-id");
			if(id){ showDetailModal(id); }
		});

		//Open HSL Definition file
		$(document).on("click", ".link-OpenHSL", function () {
			var file_path = $(this).closest(".link-card-container").attr("data-filepath");
			if(file_path && file_path !== ""){
				nw.Shell.openItem(file_path);
			}
		});

        //Run a method when clicking a card in the main div
		$(document).on("click", ".link-run-trigger", function () {
			var file_type = $(this).closest(".link-card-container").attr("data-type");
			var file_path = $(this).closest(".link-card-container").attr("data-filepath");
			var id = $(this).closest(".link-card-container").attr("data-id");
			var isCustomLink= ($(this).closest(".link-card-container").attr("data-default") == 'false');

			if(isCustomLink){
				addLinkToRecent(id);
				updateLastStarted(id);
			}
			

			if(file_type=="method"){
				var arg="";
				if($("#chk_run-autoplay").prop("checked")){ arg="-r";} //Run method immediately.
				if($("#chk_run-autoclose").prop("checked")){arg="-t";} //Run method immediately and terminate when method is complete.
    
				 var child =  spawn(HxRun, [file_path, arg], { detached: true, stdio: [ 'ignore', 'ignore', 'ignore' ] });
				 child.unref();
			}
			if(file_type=="folder"){
				nw.Shell.openItem(file_path);
				// nw.Shell.showItemInFolder(file_path);

			}
			if(file_type=="file"){
				nw.Shell.openItem(file_path);
			}
		});


		//Open attachment of a link card in the main div
		$(document).on("click", ".link-attachment", function () {
			var file_path = $(this).attr("data-filepath");	
			if(file_path!=""){
				nw.Shell.openItem(file_path);
			}	
		});

		//Open In Method Editor link card in the main div
		$(document).on("click", ".link-OpenMethEditor", function () {
			
			var file_path = $(this).closest(".link-card-container").attr("data-filepath");
			// console.log("Open in Method Editor " + file_path)
			if(file_path!=""){
				file_path = file_path.substr(0, file_path.lastIndexOf(".")) + ".med";
				nw.Shell.openItem(file_path);
			}	
		});

		//Open Method Location link card in the main div
		$(document).on("click", ".link-OpenMethLocation", function () {
			
			var file_path = path.dirname($(this).closest(".link-card-container").attr("data-filepath"));
			// console.log("Open Location " + file_path);
			if(file_path!=""){
				nw.Shell.openItem(file_path);
			}	
		});

		

		//Click simulation toggle
		$(document).on("click", "#simulation-switch", function () {
			//SetSimulation()
			if($(this).prop("checked")){
				console.log("Simulation is on");
				updateSimulationSwitch(1);
				SetSimulation("on");
			}else{
				console.log("Simulation is off");
				updateSimulationSwitch(0);
				SetSimulation("off");
			}
		});


		//Click "settings" button from main screen top nav.
		$(document).on("click", ".btn-settings", function () {
			$(".methods-page").toggleClass("d-none");
			$(".settings-page").toggleClass("d-none");
			if(!$(".settings-page").hasClass("d-none")){
				//opening settings screen
				bool_treeChanged = false;
				$(this).text('Home');
				fitSettingsDivHeight();
			}else{
				//coming back to home screen 
				$(this).text('Settings');
				if (bool_treeChanged){
					createGroups();
				}else{
					fitNavBarItems();
					fitMainDivHeight();
				}
			}  
			return false;
		});

		//Settings screen menu navigation
		$(document).on("click", ".h-menu>li>a", function () {
			$(".h-menu>li>a").removeClass("active");
			$(this).addClass("active");

			if($(this).attr('data-div') == "settings-settings"){
				$(".settings-settings").removeClass("d-none");
				$(".settings-links").addClass("d-none");
				$(".btn-newgroup").addClass("d-none");
			}else{
				$(".settings-settings").addClass("d-none");
				$(".settings-links").removeClass("d-none");
				$(".btn-newgroup").removeClass("d-none");
			}


		});

		//Settings>settings > simulation checkbox
		$(document).on("click", "#chk_settingSimulation", function(){
			saveSetting($(this).attr("id"),$(this).prop("checked"));
			$("#simulation-switch").prop("disabled",!$(this).prop("checked"))
		});

		//Settings>settings > Run control
		$(document).on("click", "#chk_run-autoplay", function(){
			saveSetting($(this).attr("id"),$(this).prop("checked"));
			if($(this).prop("checked")){
				$("#chk_run-autoclose").prop("checked",false);
				saveSetting("chk_run-autoclose",false);
			}
		});
		$(document).on("click", "#chk_run-autoclose", function(){
			saveSetting($(this).attr("id"),$(this).prop("checked"));
			if($(this).prop("checked")){
				$("#chk_run-autoplay").prop("checked",false);
				saveSetting("chk_run-autoplay",false);
			}
		});
		

		//Settings>settings > show on start up
		$(document).on("click", "#settings-startupLast", function (){
			saveSetting("startup-lastOpened",true);
			var group_id = $(".navbar-custom").find(".active").attr("data-group-id")
			saveSetting("startup-tab",group_id);
			;
		});

		$(document).on("click", "#settings-startupTab", function (){
			saveSetting("startup-lastOpened",false);
			//find the element in the dropdown div with matching text and get the group-id
			var group_name = $("#dd-navgroups").text();
			var group_id = $('.dd-navgroups a:contains("' + group_name + '")').attr("data-group-id") ;
			saveSetting("startup-tab",group_id);
		});

		//Settings-Settings-recent dropdown change text
		$(document).on("click", ".dd-maxRecent a", function () {
			var txt = $(this).text();
			$("#dd-maxRecent").text(txt);
			saveSetting("recent-max",txt);
		});

		$(document).on("click", ".btn-clearRecentList", function () {
			clearRecentList();
			$(".txt-recentCleared").text("Recent list has been cleared!");
			setTimeout(function(){ 
				$(".txt-recentCleared").text("");
			 }, 3000);
		});

		//Settings-Settings-history cleanup checkbox
		$(document).on("change, click", "#chk_settingHistoryCleanup",function(){
			var val=!$(this).prop("checked");
			//remove 'disabled' from the radio buttons and the clean up now button if the checkbox is ticked
			$("#radio_settingHistory-delete,#radio_settingHistory-archive,.btn-history-cleanup, .btn-historyMax").prop("disabled",val);
			saveSetting($(this).attr("id"), $(this).prop("checked"));
		});
		$(document).on("click", ".btn-history-cleanup" ,function(){
			historyCleanup();
		});

		//Settings-Settings-history cleanup radio buttons
		$(document).on("click", "#radio_settingHistory-delete" ,function(){
			saveSetting("cleanup-action","delete");
		});
		$(document).on("click", "#radio_settingHistory-archive" ,function(){
			saveSetting("cleanup-action","archive");
		});

		//Settings-Settings-history dropdown change text
		$(document).on("click", ".dd-historyCleanup a", function () {
			var txt = $(this).text();
			$("#dd-historyCleanup").text(txt);
			saveSetting("history-days",$(this).attr("data-days"));
		});

		//Settings-Settings-startup dropdown change text
		$(document).on("click", ".dd-navgroups a", function () {
			var txt = $(this).text();
			$("#dd-navgroups").text(txt);
			if($("#settings-startupTab").prop("checked")){
				saveSetting("startup-tab",$(this).attr("data-group-id"));	
			}
			
		});

		//Settings - settings - shortcuts --- top nav bar Folder, Run History and Editors 
		$(document).on("click", ".parent-checkbox", function(){
				//check/uncheck all children checkboxes in the settings
				$(this).parent().parent().find(".ml-4 .custom-control-input").prop('checked', $(this).prop('checked'));
				$(this).parent().parent().find(".ml-4 .custom-control-input").trigger("change");	
		});

		//Settings - settings - shortcuts --- top nav bar Folder, Run History and Editors 
		$(document).on("change", ".parent-checkbox", function (){
			
			saveSetting($(this).attr("id"),$(this).prop("checked"));

			var navitem=$(".nav-item[data-group-id='"+ $(this).attr("data-group-id") +"']");
			
			//show/hide item in the navbar of the home screen
			$(this).prop('checked') ? navitem.removeClass("d-none") : navitem.addClass("d-none");
			
			// if unchecked, hide the group-container div in the home screen
			if (!$(this).prop('checked')) {
				$(".group-container[data-group-id='"+ $(this).attr("data-group-id") +"']").addClass("d-none");
			}else{
				if(navitem.hasClass("active")){$(".group-container[data-group-id='"+ $(this).attr("data-group-id") +"']").removeClass("d-none")}
			}

		});

		//Settings - settings - shortcuts --- top nav bar Folder, Run History and Editors  - children boxes
		$(document).on("change", ".child-checkboxes input", function(){

			saveSetting($(this).attr("id"),$(this).prop("checked"));

			var parentCheckbox = $(this).parent().parent().parent().find(".parent-checkbox");
			var navitem = $(".methods-page").find("div[data-id='" + $(this).attr("data-id") + "']");
			
			//show/hide item in the group-container in home screen
			$(this).prop('checked') ? navitem.addClass("d-flex").removeClass("d-none") : navitem.addClass("d-none").removeClass("d-flex");
		
			//if this checked and parent is unchecked, check parent and show navbar 
			if ($(this).prop("checked") && !parentCheckbox.prop("checked")){
				parentCheckbox.prop("checked", true);
				parentCheckbox.trigger("change");
			}

			//if this is unchecked and all siblings are unchecked and parent is checked, uncheck the parent and hide the navbar.
			if (!$(this).prop("checked") && $(this).parent().parent().find("input:checked").length==0 && parentCheckbox.prop("checked")){
				parentCheckbox.prop("checked", false);
				parentCheckbox.trigger("change");
			}
		});

		// Settings > Links > favorite icon click
		$(document).on("click", ".favorite-icon", function (e) {
			bool_favorite = false;
			if($(this).hasClass("favorite")){
				//it´s already a favorite , deselect
				$(this).removeClass("favorite");
				$(this).find("i").removeClass("fas").addClass("far");
			}else{
				//make  favorite, select
				bool_favorite = true;
				$(this).addClass("favorite");
				$(this).find("i").removeClass("far").addClass("fas");
				
			}

			//Update favorite state in database
			if($(this).parent().attr("data-id")){
				// method / link
				id = $(this).parent().attr("data-id");
				updateFavorite(id, bool_favorite, "link");
			}else{
				// group
				id = $(this).parent().parent().attr("data-group-id");
				updateFavorite(id, bool_favorite, "group");
			}
			bool_treeChanged = true;
			e.stopPropagation();
		});


		//Edit Modal window events
		// $(document).on("click", "#editModal .inputType-radio input", function (e) {
		// 	$("#btn-filebrowse").attr("data-type", $(this).attr("data-type"));
		// });

		$(document).on("click", ".btn-filebrowse", function (e) {
			$("#" + $(this).attr("data-type") ).trigger("click");
			$("#editModal .filetype-tmpselection").attr("data-fileType",$(this).attr("data-filetype"));
		});

		$(document).on("change", "input[type='file']", function() {
			var text_control = $(this).attr("data-text-input");
			var str = $(this).val();
			$("." + text_control).val(str);
			$("." + text_control).tooltip({
				title: str,
				delay: { show: 500, hide: 100 }
			});
			
			if(str!=""){
				//Remove any red styling when setting a string.
				$("." + text_control).css({
					"border": "",
					"background": ""
				});

				//Show X to clear the field
				$("." + text_control).closest(".form-group").find(".clear-field").removeClass("d-none");
				var filetype = $("#editModal .filetype-tmpselection").attr("data-fileType");
				$("#editModal .filetype-selection").attr("data-fileType",filetype);
			}else{
				//Hide X to clear the field
				$("." + text_control).closest(".form-group").find(".clear-field").addClass("d-none");
			}

			if($(this).attr('id')=='input-image'){
				if(str!=""){
					//show image
					$(".editModal-image").attr("src", str);
					$(".editModal-image").removeClass("d-none");
					$(".image-placeholder").addClass("d-none");
				}
			}
			if($(this).attr("id")=="input-history-archiveDir"){
				saveSetting("history-archive-folder",str);
			}

		  });

		

		  $('#editModal .btn-save').click(function (e) {
            var isValid = true;
			var str_selector="#editModal .txt-linkName";
			if($("#editModal .modal-content").attr("data-linkOrGroup") == "link"){
				str_selector += ",.txt-filepath"; //if it´s a link, add this field to the validation
			}

            $(str_selector).each(function () {
                if ($.trim($(this).val()) == '') {
                    isValid = false;
                    $(this).css({
                        "border": "1px solid red",
                        "background": "#FFCECE"
                    });
					$("#editModal .div-form").removeClass("d-none");
					$("#editModal .div-iconselect").addClass("d-none");
					$("#editModal .a-choose").removeClass("d-none");
                }
                else {
                    $(this).css({
                        "border": "",
                        "background": ""
                    });
                }
            });
            if (isValid == false){
				e.preventDefault();
			}else{
				saveModalData();
			}
        });

		$(document).on("change keydown keyup", "#editModal .txt-linkName",function(e){
			if ($.trim($(this).val()) != ''){
				//Remove any red styling when setting a string in this field
				$(this).css({
					"border": "",
					"background": ""
				});
				$(this).parent().find(".clear-text").removeClass("d-none");
			} else{
				$(this).parent().find(".clear-text").addClass("d-none");
			}
			if(e.type=="keydown" && e.keyCode==13){ //pressed enter
				$("#editModal .btn-save").trigger("click");
			}
		});

		$(document).on("click", "#editModal .clear-text",function(){
			$("#editModal .txt-linkName").val('');
			$(this).addClass("d-none");
		});

		$(document).on("click", ".clear-field",function(e){
			$(this).closest(".form-group").find("input[type='file']").val('');
			$(this).closest(".form-group").find("input[type='text']").val('');
			//remove tooltip
			$(this).closest(".form-group").find("input[type='text']").tooltip("dispose");
			$(this).addClass("d-none");

			
			if($(this).closest(".form-group").find("input[type='file']").attr('id')=='input-image'){
					//show placeholder
					$(".editModal-image").attr("src", '');
					$(".editModal-image").addClass("d-none");
					$(".image-placeholder").removeClass("d-none");
			}
			
		});

		$(document).on("click", ".icon-container, .image-container, .a-choose , .close-imagediv", function(){
			if($("#editModal .div-form").hasClass("d-none")){
				//The dialog is not showing the form, need to go back to the form
				$("#editModal .div-form").removeClass("d-none");
				$("#editModal .div-iconselect").addClass("d-none");
				$("#editModal .a-choose").removeClass("d-none");
			}else{

				$("#editModal .div-form").addClass("d-none");
				$("#editModal .div-iconselect").removeClass("d-none");
				$("#editModal .a-choose").addClass("d-none");
				$("#inputImg-image, #inputImg-icon").prop("checked",false);

				//The dialog is  showing the form, need to switch to image/icon edit view
				if($("#editModal .icon-container").hasClass("d-none")){
					//Show image editing
					$("#inputImg-image").prop("checked",true);
					$("#inputImg-image").trigger("click");
				}else{
					//Show icon editing
					$("#inputImg-icon").prop("checked",true);
					$("#inputImg-icon").trigger("click");
					$("#editModal .icons-list").scrollTop(0); //reset div scroll
					//Scroll icons-list to view the selected icon
					var icon = $(".editModal-icon").attr("data-iconClass");
					var containerOffset = $("#editModal .icons-list").offset().top;
					var childOffset = $("#editModal .icons-list i." + icon).parent().offset().top;
					var calcScrollOffset = childOffset - containerOffset;
					$("#editModal .icons-list").scrollTop(calcScrollOffset - 30);
				}
			}

			
		})


		//MODAL WINDOW - ICON Color Selection
		$(document).on("mouseover", "#editModal .color-circle", function(){
			var new_color = $(this).attr("data-colorClass")
			var current_color = $(".editModal-icon").attr("data-colorClass");
			if(new_color != current_color){
				$(".editModal-icon").removeClass (current_color);
				$(".editModal-icon").addClass(new_color);
			}
		});

		$(document).on("mouseout", "#editModal .color-circle", function(){
			var new_color = $(this).attr("data-colorClass")
			var current_color = $(".editModal-icon").attr("data-colorClass");
			if(new_color != current_color){
				$(".editModal-icon").removeClass(new_color);
				$(".editModal-icon").addClass (current_color);
			}
			
		});

		$(document).on("click", "#editModal .color-circle", function(){
			var new_color = $(this).attr("data-colorClass")
			var current_color = $(".editModal-icon").attr("data-colorClass");
			if(new_color != current_color){
				$(".editModal-icon").removeClass (current_color);
				$(".editModal-icon").addClass(new_color);
				$(".editModal-icon").attr("data-colorClass", new_color);
				$("#editModal .color-circle").removeClass("color-circle-active");
				$(this).addClass("color-circle-active");
			}

		});

		

		//MODAL WINDOW - ICON type Selection
		$(document).on("mouseover", "#editModal .select-icon", function(){
			var new_icon= $(this).find("i").attr('class').replace("fas fa-1x ","");
			var current_icon = $(".editModal-icon").attr("data-iconClass");
			if(new_icon != current_icon){
				$(".editModal-icon").removeClass (current_icon);
				$(".editModal-icon").addClass(new_icon);
			}
		});

		$(document).on("mouseout", "#editModal .select-icon", function(){
			var new_icon = $(this).find("i").attr('class').replace("fas fa-1x ","");
			var current_icon = $(".editModal-icon").attr("data-iconClass");
			if(new_icon != current_icon){
				$(".editModal-icon").removeClass(new_icon);
				$(".editModal-icon").addClass (current_icon);
			}
			
		});

		$(document).on("click", "#editModal .select-icon", function(){
			var new_icon = $(this).find("i").attr('class').replace("fas fa-1x ","");
			var current_icon = $(".editModal-icon").attr("data-iconClass");
			if(new_icon != current_icon){
				$(".editModal-icon").removeClass (current_icon);
				$(".editModal-icon").addClass(new_icon);
				$(".editModal-icon").attr("data-iconClass", new_icon);
				$("#editModal .select-icon").removeClass("icon-active");
				$(this).addClass("icon-active");
			}

		});
		

		//MODAL WINDOW - Radio selection Icon / Image
		$(document).on("click","#inputImg-image",function(e){
			$("#image-selection").removeClass("d-none");
			$("#icon-selection").addClass("d-none");
			$(".image-container").removeClass("d-none");
			$(".icon-container").addClass("d-none");
			if($("#editModal .txt-image").val()==''){
				//no path selected for image. Display icon placeholder
				$(".editModal-image").addClass("d-none");
				$(".image-placeholder").removeClass("d-none");
			}else{
				//img path selected . Display image
				$(".editModal-image").removeClass("d-none");
				$(".image-placeholder").addClass("d-none");
			}
		});


		$(document).on("click","#inputImg-icon",function(){
			$("#image-selection").addClass("d-none");
			$("#icon-selection").removeClass("d-none");
			$(".image-container").addClass("d-none");
			$(".icon-container").removeClass("d-none");
			$("#editModal .icons-list").scrollTop(0); //reset div scroll
			//Scroll icons-list to view the selected icon
			var icon = $(".editModal-icon").attr("data-iconClass");
			$("#editModal .select-icon").removeClass("icon-active");
			$("#editModal .icons-list i." + icon).parent().addClass("icon-active");
			var containerOffset = $("#editModal .icons-list").offset().top;
			var childOffset = $("#editModal .icons-list i." + icon).parent().offset().top;
			var calcScrollOffset = childOffset - containerOffset;
			$("#editModal .icons-list").scrollTop(calcScrollOffset - 30);
			//hightlight color
			var color=$(".editModal-icon").attr("data-colorClass");
			$("#editModal .color-circle").removeClass("color-circle-active");
			$("#editModal .color-circle."+color).addClass("color-circle-active");

		});
		


		$(document).on("click", ".btn-newgroup", function(){
			groupNew();
		})
		$(document).on("click", ".btn-newlink", function(){
			var group_id = $(this).closest("div[data-group-id]").attr("data-group-id");
			linkNew(group_id);
		})

		$(document).on("click", ".group-name",function (e){
			var id=$(this).closest("[data-group-id]").attr("data-group-id");
			editModal("group","edit",id);
			e.stopPropagation();
		})

		$(document).on("click", ".settings-links-method",function (e){
			var id=$(this).attr("data-id");
			editModal("link","edit",id);
		})

		$(document).on("click", "#editModal .btn-delete",function (e){
			var id=$("#editModal .modal-content").attr("data-id");
			var linkOrGroup = $("#editModal .modal-content").attr("data-linkOrGroup");
			$("#editModal").modal("hide");
			confirmDeleteModal(id, linkOrGroup);
		})
		

		$(document).on('shown.bs.modal', '#editModal', function () {
			if($("#editModal .txt-linkName").val()==''){
				$("#editModal .txt-linkName").focus();
			}
		});

		$(document).on("click",".username-logoff",function(){
			bool_isHamUserChangeClick = true;
			GetFunctionProtection("null",HandleFunctionProtection);

		})
		
        //*************************************************************************
        //******  EVENTS END*******************************************************
        //*************************************************************************



        //**************************************************************************************
        //******  FUNCTION DECLARATIONS  *******************************************************
        //**************************************************************************************
		var waitForFinalEvent = (function () {
			var timers = {};
			return function (callback, ms, uniqueId) {
				if (!uniqueId) {
					uniqueId = "Don't call this twice without a uniqueId";
				}
				if (timers[uniqueId]) {
					clearTimeout(timers[uniqueId]);
				}
				timers[uniqueId] = setTimeout(callback, ms);
			};
		})();



        // Adjusts the main div height to the window size and display a y-scrollbar only in that section
		function fitMainDivHeight() {
			if($(".methods-page").hasClass("d-none")){return;} //exit function if settings page is not visible
			var linksDiv = $(".links-container");
			var linksDiv_height = window.innerHeight - $(".header1").outerHeight() - $(".header2").outerHeight();
			var linksDiv_padding = parseInt($(linksDiv).css('padding-top')) + parseInt($(linksDiv).css('padding-bottom')) + parseInt($(linksDiv).css('margin-bottom'));
			linksDiv_height -= linksDiv_padding;
			$(linksDiv).height(linksDiv_height);
		}


		//Adjust the settings page div height
		function fitSettingsDivHeight() {
			if($(".settings-page").hasClass("d-none")){return;} //exit function if settings page is not visible
			var linksDiv = $(".setttings-container");
			var div1 = $(".settings-page>.row");
			var linksDiv_height = window.innerHeight - $(".header1").outerHeight() - $(".nav-settings").outerHeight();
			var linksDiv_padding = parseInt($(div1).css('padding-top')) + parseInt($(div1).css('padding-bottom')) + parseInt($(div1).css('margin-bottom')) + parseInt($(".nav-settings").css('margin-bottom'));
			linksDiv_height -= linksDiv_padding;
			$(linksDiv).height(linksDiv_height);
		}


        // Adjusts the elements in the nav bar and hides the ones that exceed the total width available
		function fitNavBarItems() {
			if($(".methods-page").hasClass("d-none")){return;} //exit function if settings page is not visible
			// horizontal room we have to work with (the container)
			// this value doesn't change until we resize again
			var navSpace = $('.navbar-custom').width();
			// calc the combined width of all nav-items
			var linksWidth = 0;
			$('.nav-subgroup').each(function () {
				linksWidth += $(this).outerWidth();
			});
			// now let's compare them to see if all the links fit in the container...
			if (linksWidth > navSpace) {
				// the width of the links is greater than the width of their container...
				// keep moving links from the menu to the overflow until the combined width is less than the container...
				while (linksWidth > navSpace) {
					var lastLink = $('.navblock-collapsable > li:last'); // get the last link
					
						var lastLinkWidth = lastLink.outerWidth(); // get its width
						var lastLinkIconClass = $(lastLink).find('i').attr("class").toString().replace("fa-1x", "fa-sm");
						$(lastLink).data('foo', lastLinkWidth); // store the width (so that we can see if it fits back in the space available later)
						var str = $(lastLink).find('.nav-item-text').text();

						$('.hidden-nav-items').prepend(lastLink);
						
						var strClass = ""
						if($(lastLink).hasClass("d-none")){ strClass = " d-none"}
						
						$('#nav-overflow').prepend(
							'<a class="dropdown-item dropdown-navitem'+ strClass +'" href="#"><i class="' + lastLinkIconClass + ' mr-2"></i>' + str + '</a>'
						); // pop the link and push it to the overflow
						// recalc the linksWidth since we removed one
						linksWidth = 0;
						$('.nav-subgroup').each(function () {
							linksWidth += $(this).outerWidth();
						});
	
				}
				$('#nav-more').removeClass("d-none"); // make sure we can see the overflow menu
				$('#navbarDropdownMenuLink').text('+' + $('#nav-overflow > a').length); // update the hidden link count
			} else {
				// shazam, the width of the links is less than the width of their container...
				// let's move links from the overflow back into the menu until we run out of room again...
				while (linksWidth <= navSpace) {
					var firstOverflowLink = $('.hidden-nav-items > li:first');
					var firstOverflowLinkWidth = firstOverflowLink.data('foo');
					if ($('#nav-overflow > a').length == 1) {
						linksWidth -= $('#nav-more').outerWidth();
					}
					if (navSpace - linksWidth > firstOverflowLinkWidth) {
						$('.navblock-collapsable').append(firstOverflowLink);
						$('#nav-overflow > a:first').remove();
					}
					linksWidth = linksWidth + firstOverflowLinkWidth; // recalc the linksWidth since we added one
				}
				$('#navbarDropdownMenuLink').text('+' + $('#nav-overflow > a').length);  // update the hidden link count
				// should we hide the overflow menu?
				if ($('#nav-overflow > a').length == 0) {
					$('#nav-more').addClass("d-none");
				}
			} // end else
		}

		//Generate a unique ID, used for methods and method groups.
		function uniqueID() {
			return Date.now();
		}

		
		//Create the method groups in the nav bar and the method cards in the main div
		function createGroups() {
			$(".navbarLeft>li").remove(); // delete all groups in left nav bar except the first 2 (All, Recent)
			$(".navbarRight>li").remove(); // delete all groups in right nav bar 
			$("#nav-overflow").empty();		 // delete all links added to dropdown div that handles the nav bar overflow
			$('.hidden-nav-items').empty();  // delete all links added to the hidden div to handle the nav bar overflow
			$(".links-container>.row").empty(); // delete all group containers in the main view
			
			//Empty Settings screen > Links
			$(".settings-links #accordion").empty();

			
			var navtree = db_tree.tree.find(); //loads tree of custom groups/methods structure. This excludes the system groups and links for editors & folders

			

			for (i = 0; i < navtree.length; ++i) {

				var group_id = navtree[i]["group-id"];
				var navgroup = db_groups.groups.findOne({"_id":group_id}); // loads all custom groups
				//find group data

				if(navgroup){
					var group_name = navgroup["name"];
					var group_icon = navgroup["icon-class"];
					
					var group_default = navgroup["default"];
					var group_navbar = navgroup["navbar"];
					var group_favorite = navgroup["favorite"];

					var classCustomGroup = "";
					if(!group_default){
						classCustomGroup = " custom-group ";
					}

					//add nav groups to nav bar
					var str = '<li class="nav-item' ;
					if(!group_favorite){str+=' d-none';}
					
					str +=  classCustomGroup + '" data-group-id="' + group_id + '">' +
									'<div class="navitem-content"><div><i class="far fa-1x ' + group_icon + '"></i></div>' +
									// '<i class="far fa-1x ' + group_icon + '"></i><br>' +
									'<div><span class="nav-item-text">' + group_name + '</span></div></div></li>';

					(group_navbar==="left") ?  $(".navbarLeft").append(str) : $(".navbarRight").append(str);

					//add nav groups to main div. This groups will be filled with the method cards
					var str = '<div class="row no-gutters d-none group-container w-100 '+ classCustomGroup + '" data-group-id="' + group_id + '"></div>';
					$(".links-container>.row").append(str);



					// add custom groups to settings > links
					var displayClass = "";
					if(group_default){displayClass = " d-none";}
						str = '<div class="card mb-2 settings-links-group cursor-pointer'+displayClass+'" data-group-id="'+ group_id +'">' +
								'<div class="card-header collapsed" role="tab" id="heading_'+group_id +'" data-toggle="collapse" href="#collapse_'+ group_id+'" aria-expanded="true" aria-controls="collapse_'+ group_id+'">' +
										'<span class="far fa-chevron-right mr-2 caret-right color-medium"></span>' +
										'<span class="color-medium2"><i class="fas '+ group_icon +' fa-md ml-2 mr-2"></i><span class="group-name">'+ group_name +' </span></span>'+
										'<span class="cursor-pointer float-right pl-2 pr-2 " id="ddg_'+group_id+'" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">'+
											'<i class="far fa-ellipsis-v fa-md color-grayblue"></i>'+
											'<div class="dropdown-menu" aria-labelledby="ddg_'+group_id+'">'+
												'<a class="dropdown-item dropdown-navitem-clearbg" href="#" onclick="groupEdit(\''+group_id+'\');"><i class="far fa-pencil fa-sm mr-2 color-blue"></i>Edit</a>'+
												'<a class="dropdown-item dropdown-navitem-clearbg" href="#" onclick="groupDelete(\''+ group_id +'\');"><i class="far fa-trash fa-sm mr-2 color-blue"></i>Delete</a>'+
											'</div>'+
										'</span>';
										if(group_favorite){
											str+='<span class="cursor-pointer color-medium float-right pl-2 pr-2 favorite-icon favorite tooltip-delay1000" data-toggle="tooltip" title="Show/hide in home screen"">'+
												'<i class="fas fa-star fa-md"></i>'+
											'</span>';
										}else{
											str+='<span class="cursor-pointer color-medium float-right pl-2 pr-2 favorite-icon tooltip-delay1000" data-toggle="tooltip" title="Show/hide in home screen"">'+
												'<i class="far fa-star fa-md"></i>'+
											'</span>';
										}
								str+='</div>'+  
								'<div id="collapse_'+ group_id+'" class="collapse" role="tabpanel" aria-labelledby="heading_'+group_id +'">'+
									'<div class="card-body ml-5 mr-5 pl-4 pr-4 pt-2 pb-2">'+

									'</div>'+
									'<div class="ml-5 mr-5 pl-5 mb-3">'+
										'<button class="btn btn-sm btn-outlined ml-0 btn-newlink">New Link</button>'+
									'</div>'+
								'</div>'+
							'</div>';
					$(".settings-links #accordion").append(str);


							
				    //Add the method cards to the group container in the main div in the home screen
					var method_ids = navtree[i]["method-ids"];

					for (j = 0; j < method_ids.length; ++j) {
						var method = db_links.links.findOne({"_id":method_ids[j]}); // load link with the given id
						if(method){

								var id = method["_id"]; 
								var name = method["name"];
								var description = method["description"];
								var icon_customImage = method["icon-customImage"];  //the path to a custom image, if empty use icon.
								var icon_class = method["icon-class"];
								var icon_color = method["icon-color"];
								var method_path = method["path"];
								var attachments = method["attachments"];
								var method_default = method["default"];
								var method_type = method["type"];
								var method_favorite = method["favorite"];

								//check if the given icon_customImage exists, otherwise set placeholder icon
								if(icon_customImage!="" && icon_customImage!="placeholder"){
									try {
										if(method_default){
											//Default links use relative paths for the images
											if(fs.existsSync("html/img/" + icon_customImage)) {
												//console.log("The file exists.");
												icon_customImage = "img/" + icon_customImage;
											} else {
												//console.log('The file does not exist.');
												icon_customImage = "placeholder";
											}
										}else{
											if(fs.existsSync(icon_customImage)) {
												//console.log("The file exists.");
											} else {
												//console.log('The file does not exist.');
												icon_customImage = "placeholder";
											}
										}
									} catch (err) {
										//console.error(err);
									}
								}
								

								// the dropdown will not be visible if there are no attachments and the user is not admin.
								(!attachments && !isUserAdmin) ? strTmpClass = 'd-none' : strTmpClass = ''; 

								var ddownMenu_id = "dd_" + id;
								var divAttachments = "";
								var ellipsis_class = "";
								var tooltip_text = "Click to run ";
								var paperClipIcon_class ="d-none";

								//Change tooltip text for folder link type.  
								if(method_type=="folder"){
									//ellipsis_class="d-none"
									tooltip_text = "Click to open folder "}; 

								if(method_type=="file"){
										tooltip_text = "Click to open file "}; 
								
								// build the method attachments links 
								if (attachments) {
									for (k = 0; k < attachments.length; ++k) {
										divAttachments += '<a class="dropdown-item tooltip-delay500 link-attachment cursor-pointer" href="#" data-filepath="' + attachments[k] + '" data-toggle="tooltip" title="' + attachments[k] + '">' +
											'<i class="far fa-paperclip fa-md mr-2 color-blue"></i>' + path.basename((attachments[k])) + '</a>';
										paperClipIcon_class ="";
									}
								}

								var div_linkimage="";
								var div_linkimage_small = "";
								if(icon_customImage==""){
									//icon
									div_linkimage = '<div class="link-icon m-3"><i class="fad fa-3x ' + icon_class + ' ' + icon_color + '"></i></div>';
									div_linkimage_small = '<i class="fad '+icon_class +' fa-lg ml-2 mr-2 mb-2 align-top pt-2 '+icon_color+'"></i>';
								}else{
									//image
									if(icon_customImage=="placeholder"){
										div_linkimage = '<div class="link-icon m-3"><i class="fad fa-3x fa-image color-gray"></i></div>';
										div_linkimage_small = '<i class="fad fa-image fa-lg ml-2 mr-2 mb-2 align-top pt-2 color-gray"></i>';
									}else{
										method_default ? image_dimensions = sizeOf('html/' + icon_customImage) : image_dimensions = sizeOf(icon_customImage);
										var w = image_dimensions.width;
										if(w > 200 ) {w=200};
										div_linkimage = '<div class="link-icon m-3"><img src="'+ icon_customImage +'" width="'+ w +'"></div>';
										div_linkimage_small = '<img src="'+ icon_customImage +'" class="ml-2 mr-2 mb-2 align-top pt-2" width="20">';
									}

								}

								// the Open in Method Editor and Open File Location divs will not be visible if there are no attachments and the user is not admin.
								(!isUserAdmin) ? strTmpClass2 = 'd-none' : strTmpClass2 = ''; 

								// the Open in Method Editor and Open File Location divs will only be visible for methods. Hidden for folders and other files.
								if(method_type!="method"){ strTmpClass2 = "d-none";} 

								//do not display if not a favorite
								(method_favorite) ? strDisplayClass = 'd-flex' : strDisplayClass = 'd-none'; 

								//build the method card and details dropdown
								var str = '<div class="col-md-4 col-xl-3 align-items-stretch link-card-container '+ strDisplayClass +'" data-id="'+ id + '" data-group-id="'+group_id+'"  data-filepath="' + method_path + '" data-type="' + method_type + '" data-default="'+method_default+'">' +
											'<div class="m-2 pl-3 pr-2 pt-1 pb-2 link-card">' + '<div class="float-left link-card-groupTitle">' +  group_name + '</div>' +
												'<div class="menu-icon text-right dropdown ' + strTmpClass + '">' +
													'<span class="dropdown-toggle pl-3 cursor-pointer" id="' + ddownMenu_id + '" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false"><i class="' + paperClipIcon_class + ' far fa-paperclip fa-md color-lightgray mr-2"></i>' +
													'<i class="' + ellipsis_class + ' far fa-ellipsis-v fa-md color-grayblue"></i>' +
													'</span><div class="dropdown-menu" aria-labelledby="' + ddownMenu_id + '">' + divAttachments +
														'<div class="dropdown-divider"></div>' +
														'<a class="dropdown-item link-detail-trigger cursor-pointer" href="#" data-id="' + id + '"><i class="far fa-info-circle fa-sm mr-2 color-blue"></i>View Details</a>' +
														'<a class="dropdown-item link-OpenHSL cursor-pointer" href="#"><i class="far fa-file-code fa-sm mr-2 color-blue"></i>Open HSL Definition</a>' +
														'<a class="dropdown-item ' + strTmpClass2 + ' link-OpenMethEditor  cursor-pointer" href="#"><i class="far fa-pencil fa-sm mr-2 color-blue"></i>Open in Method Editor</a>' +
														'<a class="dropdown-item ' + strTmpClass2 + ' link-OpenMethLocation  cursor-pointer" href="#" data-dir="' + path.dirname(method_path) + '"><i class="far fa-folder fa-sm mr-2 color-blue"></i>Open method location</a>' +
														'<a class="dropdown-item text-muted tooltip-delay500 link-run-trigger cursor-pointer" href="#" data-toggle="tooltip" title="' + method_path + '">' +
															'<i class="fas fa-link fa-sm mr-2 color-grayblue"></i>...\\' + path.basename(method_path) +
														'</a>' +
														'</div>' +
													'</div>' + //end of dropdown div
												'<div class="clearfix"></div>'+
												'<div class="link-detail-trigger tooltip-delay1000 cursor-pointer" data-id="' + id + '" data-toggle="tooltip" title="' + tooltip_text + name + '">' +
												div_linkimage +
												'<h5>' + name + '</h5>' +
												'<p class="text-muted">' + description + '</p>' +
												'</div>' + //end of link-detail-trigger div
												'</div>' + //end of link-card div
											'</div>';//end of col-md-4 div

								$('.group-container[data-group-id="' + group_id + '"]').append(str);


								//build the methods links in the Settings > links section
									
								var str= '<div class="settings-links-method w-100 pt-2" data-id="'+id+'">'+
														div_linkimage_small +
														'<div class="d-inline-block pb-2 link-namepath">'+
															'<div class="name">'+name+'</div>'+
															'<div class="path">'+method_path+'</div>'+
														'</div>'+
														'<span class="float-right pl-2 pr-2 " id="ddm_'+id+'" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">'+
															'<i class="far fa-ellipsis-v fa-md color-grayblue align-bottom"></i>'+
															'<div class="dropdown-menu" aria-labelledby="ddm_'+id+'">'+
																'<a class="dropdown-item dropdown-navitem-clearbg" href="#" onclick="linkEdit(\''+id+'\');"><i class="far fa-pencil fa-sm mr-2 color-blue"></i>Edit</a>'+
																'<a class="dropdown-item dropdown-navitem-clearbg" href="#" onclick="linkDelete(\''+id+'\');"><i class="far fa-trash fa-sm mr-2 color-blue"></i>Delete</a>'+
															'</div>'+
														'</span>';
														
														if(method_favorite){
															str+='<span class="color-medium  float-right pl-2 pr-2 favorite-icon favorite tooltip-delay1000" data-toggle="tooltip" title="Show/hide in home screen">'+
																	'<i class="fas fa-star fa-md align-bottom"></i></span>';
														}else{
															str+='<span class="color-medium  float-right pl-2 pr-2 favorite-icon tooltip-delay1000" data-toggle="tooltip" title="Show/hide in home screen">'+
																	'<i class="far fa-star fa-md align-bottom"></i></span>';	
														}
									
									str+='<span class="float-right pr-2 pl-2 custom-badge">'+ method_type +'</span>';	
									if(attachments){
										if (attachments.length > 0){
											str+='<span class="color-lightgray float-right pl-2 pr-2"><i class="far fa-paperclip fa-md align-bottom"></i></span>';
										}
									}			
									str+='</div>';
									$("#collapse_"+ group_id + " .card-body").append(str);


						} //end if method
					} //end for methods in navgroup
				} //end if navgroup
			} //end for groups




			// add bottom divs for the groups container, after the group divs. This creates the needed margin to properly stretch the cards
			var str = '<div class="col-md-12 my-3"></div>';
			$(".links-container>.row").append(str);


			//add groups to dropdown menu in the Settings > Settings > Start up section 
			$(".dd-navgroups").empty()  // delete all groups in the dropdown menu in the Settings > Settings > Start up section  
			$(".navbarLeft .nav-item-text").each(function() {
				$(".dd-navgroups").append('<a class="dropdown-item dropdown-navitem-clearbg" href="#" data-group-id="'+ $(this).closest("li").attr("data-group-id") +'">' + $(this).text() + '</a>');
			  });

			loadSettings();

			//Create the links in the recent group
			var arr_recent_ids = getRecentMethods(int_maxRecent);

			$(".group-container[data-group-id='gRecent']").empty();

			for (let i = 0; i < arr_recent_ids.length; i++) {
				var id=arr_recent_ids[i]["_id"];
				addLinkToRecent(id);
			}


			//Activate tooltips
			$('.tooltip-delay500').tooltip({
				delay: { show: 500, hide: 100 } //used for short paths in the link details
			});
			$('.tooltip-delay1000').tooltip({
				delay: { show: 1000, hide: 100 }  //used for prompt over method link
			});


			//reset nav bar and hide overflowing nav bar items
			fitNavBarItems();
			fitMainDivHeight();
			updateSortableDivs();
		}

		function updateSortableDivs(){
			//Sortable lists of groups and methods
			$( "#accordion" ).sortable({
				update: function(evet, ui){
					//recreate the tree.json
					saveTree();
				}
			});
			$( ".settings-links-group .card-body" ).sortable({
				connectWith: ".settings-links-group .card-body",
				update: function(event, ui ) {
					if (this === ui.item.parent()[0]) { // this avoids the update to be triggerd twice when moving between groups
						//recreate the tree.json
						saveTree();
					}
					
						
				}
			});
		}

		function saveTree(){
			console.log("save tree..");
			db_tree.tree.remove({"locked":false},true); //clean up tree.json
			var tree =[];
			var groups = $(".settings-links-group");
			for (i = 0; i < groups.length; ++i) {
				var methods = $(groups[i]).find(".settings-links-method");
				var method_ids=[]
				for (j = 0; j < methods.length; ++j) {
					var id= $(methods[j]).attr("data-id");
					method_ids.push(id); //get method id
				}
				var obj = {};
				obj["group-id"] =$(groups[i]).attr('data-group-id'); // get group id
				obj["method-ids"] = method_ids;
				obj["locked"] = false;  // added to be used as a filter with the diskdb remove function to clear the tree.json without deleting the file.
				tree.unshift(obj); //pushes obj to the beginning of the array. This allows showing the groups in order when diskdb saves it.
			}
			db_tree.tree.save(tree);
			bool_treeChanged = true;
		}

		function updateFavorite(id , bool_favorite , linkOrGroup){
			var query = { "_id" : id};
			var dataToBeUpdate = {"favorite": bool_favorite};
			var options = {multi: false,upsert: false};
			if(linkOrGroup=="link"){
				var updated = db_links.links.update(query, dataToBeUpdate, options);
				//console.log(updated); // { updated: 1, inserted: 0 }
			}
			if(linkOrGroup=="group"){
				var updated = db_groups.groups.update(query, dataToBeUpdate, options);
				//console.log(updated); // { updated: 1, inserted: 0 }
			}
		}

		function linkNew(group_id){
			editModal("link","new",group_id);
		}

		function linkEdit(id){
			editModal("link","edit",id);
		}
		function linkDelete(id){
			confirmDeleteModal(id, "link");
		}

		function showDetailModal(id){
			var method = db_links.links.findOne({"_id": id});
			if(!method) return;

			var name = method["name"] || "";
			var description = method["description"] || "";
			var icon_customImage = method["icon-customImage"] || "";
			var icon_class = method["icon-class"] || "fa-file";
			var icon_color = method["icon-color"] || "color-dark";
			var method_path = method["path"] || "";
			var method_type = method["type"] || "";
			var attachments = method["attachments"] || [];
			var version = method["version"] || "—";
			var buildNumber = method["build-number"] || "—";
			var customFields = method["custom-fields"] || {};

			// Set icon or image
			var $icon = $("#detailModal .detail-modal-icon");
			$icon.empty();
			if(icon_customImage && icon_customImage !== "" && icon_customImage !== "placeholder"){
				var imgExists = false;
				try { imgExists = fs.existsSync(icon_customImage); } catch(e){}
				if(!imgExists && method["default"]){
					try { imgExists = fs.existsSync("html/img/" + icon_customImage); } catch(e){}
					if(imgExists) icon_customImage = "img/" + icon_customImage;
				}
				if(imgExists){
					$icon.html('<img src="' + icon_customImage + '">');
				} else {
					$icon.html('<i class="fad fa-image fa-3x color-gray"></i>');
				}
			} else {
				$icon.html('<i class="fad ' + icon_class + ' fa-3x ' + icon_color + '"></i>');
			}

			// Set name and type
			$("#detailModal .detail-modal-name").text(name);
			$("#detailModal .detail-modal-type").text(method_type);

			// Set description
			if(description){
				$("#detailModal .detail-modal-description").text(description).closest(".detail-section").removeClass("d-none");
			} else {
				$("#detailModal .detail-modal-description").closest(".detail-section").addClass("d-none");
			}

			// Set file path
			$("#detailModal .detail-modal-path").text(method_path);

			// Set version and build number
			$("#detailModal .detail-modal-version").text(version);
			$("#detailModal .detail-modal-buildnumber").text(buildNumber);

			// Build custom fields
			var $customList = $("#detailModal .detail-custom-fields-list");
			$customList.empty();
			var hasCustom = false;
			if(customFields && typeof customFields === "object"){
				var keys = Object.keys(customFields);
				for(var c = 0; c < keys.length; c++){
					hasCustom = true;
					$customList.append(
						'<div class="detail-field-row">' +
							'<span class="detail-field-key">' + keys[c] + '</span>' +
							'<span class="detail-field-value">' + customFields[keys[c]] + '</span>' +
						'</div>'
					);
				}
			}
			if(hasCustom){
				$("#detailModal .detail-custom-fields").removeClass("d-none");
			} else {
				$("#detailModal .detail-custom-fields").addClass("d-none");
			}

			// Build attachments
			var $attList = $("#detailModal .detail-attachments-list");
			$attList.empty();
			if(attachments && attachments.length > 0){
				for(var a = 0; a < attachments.length; a++){
					$attList.append(
						'<a href="#" class="link-attachment" data-filepath="' + attachments[a] + '">' +
							'<i class="far fa-paperclip fa-sm mr-2 color-blue"></i>' + path.basename(attachments[a]) +
						'</a>'
					);
				}
				$("#detailModal .detail-attachments-section").removeClass("d-none");
			} else {
				$("#detailModal .detail-attachments-section").addClass("d-none");
			}

			$("#detailModal").modal("show");
		}

		function groupNew(){
			editModal("group","new","");
		}
		function groupEdit(id){
			editModal("group","edit",id);
		}
		function groupDelete(id){
			confirmDeleteModal(id, "group");
		}

		function confirmDeleteModal(id, linkOrGroup){
			$('#deleteModal').modal();
			$('#deleteModal .btn-delete').attr("onclick", "deleteData('"+id+"','"+ linkOrGroup + "')");
			$("#deleteModal .linkorgroup").text(linkOrGroup);
			
			var str="";
			if(linkOrGroup == "link"){
				str = $(".settings-links-method[data-id='" +id+"'] .name").text();
			}
			if(linkOrGroup == "group"){
				str = $(".settings-links-group[data-group-id='" +id+"'] .group-name").text();
			}

			$("#deleteModal .name").text(str);
		}     


		function deleteData(id , linkOrGroup,callback){
				if(linkOrGroup == "link"){
					var el = $(".settings-links-method[data-id='" +id+"']");
				}
				if(linkOrGroup == "group"){
					var el = $(".settings-links-group[data-group-id='" +id+"']");
				}

				if(el){
					var highlight_color = getComputedStyle(document.body).getPropertyValue('--medium');
					el.effect( "highlight", {color: highlight_color}, 500, 
					function(){
						el.hide( "drop", { direction: "right" }, 500, function(){
							el.remove();
							saveTree()
						});
					});
					//remove from db
					if(linkOrGroup == "group"){
						 db_groups.groups.remove({"_id": id });
						//delete all children links
						var children_Links = el.find(".settings-links-method");
						for (let i = 0; i < children_Links.length; i++) {
							var link_id = $(children_Links[i]).attr("data-id");
							console.log(link_id);
							db_links.links.remove({"_id": link_id });
						}
					}
					if(linkOrGroup == "link") { db_links.links.remove({"_id": id });}
				}
				
				$('#deleteModal').modal('hide'); // now close modal
		} 

		function saveModalData(){

			var linkOrGroup = $("#editModal .modal-content").attr("data-linkOrGroup");
			var newOrEdit = $("#editModal .modal-content").attr("data-newOrEdit");
			var name = $('#editModal .txt-linkName').val()
			var icon_class = $("#editModal .editModal-icon").attr("data-iconClass");
			var icon_color = $("#editModal .editModal-icon").attr("data-colorClass");

			if(linkOrGroup == "link"){
				var description = $('#editModal .txt-description').val();
				if(!description){description=""};
				var link_path = $('#editModal .txt-filepath').val();
				var filetype = $("#editModal .filetype-selection").attr("data-fileType");
				var attachments = [];
				for (i = 1; i < 4; i++) {
					var attachment = $("#editModal .txt-attach"+i).val();
					if ($.trim(attachment) != ''){
						attachments.push(attachment);
					}
				}
				var version = $('#editModal .txt-version').val() || "";
				var buildNumber = $('#editModal .txt-buildnumber').val() || "";
				var customFieldsText = $('#editModal .txt-customfields').val() || "";
				var customFields = {};
				if(customFieldsText.trim() !== ""){
					var cfLines = customFieldsText.split("\n");
					for(var cf = 0; cf < cfLines.length; cf++){
						var eqIndex = cfLines[cf].indexOf("=");
						if(eqIndex > 0){
							var key = cfLines[cf].substring(0, eqIndex).trim();
							var val = cfLines[cf].substring(eqIndex + 1).trim();
							if(key !== "") customFields[key] = val;
						}
					}
				}

				var icon_customImage = "";
				if($("#inputImg-image").prop("checked")){
					icon_customImage = $('#editModal .txt-image').val();
					if(icon_customImage==""){
						icon_customImage ="placeholder";
					}else{
						//check if the given icon_customImage exists, otherwise set placeholder icon
						if(icon_customImage!="" && icon_customImage!="placeholder"){
							try {
								if(fs.existsSync(icon_customImage)) {
									//console.log("The file exists.");
								} else {
									//console.log('The file does not exist.');
									icon_customImage = "placeholder";
								}
							} catch (err) {
								//console.error(err);
							}
						}
					}
				}
				

				if(newOrEdit =="edit"){
				//EDIT LINK
				
					var dataToSave = {
						"name": name,
						"description": description,
						"icon-customImage": icon_customImage,
						"icon-class": icon_class,
						"icon-color": icon_color,
						"path": link_path,
						"type": filetype,
						"attachments": attachments,
						"version": version,
						"build-number": buildNumber,
						"custom-fields": customFields
					};

					//SAVE LINK DATA
					var id = $("#editModal .modal-content").attr("data-id");
					var query = { "_id" : id };
					
					var options = {
						multi: false,
						upsert: false
					};
					var updated = db_links.links.update(query, dataToSave, options);
					// console.log(updated); // { updated: 1, inserted: 0 }
					var group_id = $(".settings-links-method[data-id='" + id + "']").closest(".settings-links-group").attr("data-group-id");
				}
				if(newOrEdit =="new"){
					//NEW LINK
					var dataToSave = {
						"name": name,
						"description": description,
						"icon-customImage": icon_customImage,
						"icon-class": icon_class,
						"icon-color": icon_color,
						"path": link_path,
						"type": filetype,
						"attachments": attachments,
						"default": false,
						"favorite": true,
						"last-started": "",
						"last-startedUTC": 0,
						"version": version,
						"build-number": buildNumber,
						"custom-fields": customFields
					};
					var saved = db_links.links.save(dataToSave);
					
					var method_id = saved._id;					
					var group_id = $("#editModal .modal-content").attr("data-id");

					//**********************save method id into tree.json
					//**********************
					//Add new method dummy div with method id to the tree and regenerate the tree.json. The whole and links will be recreated after saving the modal.
					var str='<div class="settings-links-method" data-id="'+method_id+'"></div>'
					$(".settings-links-group[data-group-id='"+group_id+"'").find(".card-body").append(str)
					
					saveTree();

					
				}
			}
			if(linkOrGroup == "group"){
				var dataToSave = {
					"name": name,
					"icon-class": icon_class,
					"default": false, 
					"navbar": "left",
					"favorite": true
				};

				if(newOrEdit =="edit"){
					//SAVE GROUP DATA
					var id = $("#editModal .modal-content").attr("data-id");
					var group_id = id;
					var query = { "_id" : id };
					
					var options = {
						multi: false,
						upsert: false
					};
					var updated = db_groups.groups.update(query, dataToSave, options);
					// console.log(updated); // { updated: 1, inserted: 0 }
				}
				if(newOrEdit =="new"){
					var saved = db_groups.groups.save(dataToSave);
					var group_id = saved._id;					

					//**********************save group id into tree.json
					//**********************
					//Add new group dummy div with group id to the tree and regenerate the tree.json. All links will be recreated after saving the modal.
					var str='<div class="settings-links-group" data-group-id="'+group_id+'"></div>'
					$("#accordion").append(str);
					
					saveTree();
				}
			}
		
			createGroups();
			$("#editModal").modal('hide');
			// console.log("group_id =" + group_id );
			$("#collapse_"+group_id).collapse("show"); //expand the group 
			

		}

		function editModal(linkOrGroup, newOrEdit, id){

			$("#editModal .modal-content").attr("data-linkOrGroup",linkOrGroup);
			$("#editModal .modal-content").attr("data-newOrEdit",newOrEdit);
			$("#editModal .modal-content").attr("data-id",id);
			$("#editModal .modal-title").text(newOrEdit + " " + linkOrGroup);

			$('#editModal .txt-linkName,.txt-filepath').each(function () {
               //clear any red styles
                    $(this).css({
                        "border": "",
                        "background": ""
                    });
            });

			$("#editModal .clear-field").addClass("d-none"); //hide all 'X' icons next to a file input field.
			$("#editModal .clear-text").addClass("d-none"); //hide X inside text input field
			$("#editModal .a-choose").removeClass("d-none"); //show "Choose..." under the icon/image

			//get data from database
			if(linkOrGroup == "link"){
				
				//hide link or image related divs
				$("#editModal .image-container").addClass("d-none");
				$("#editModal .icon-container").addClass("d-none");
				$("#editModal .div-form").removeClass("d-none");
				$("#editModal .link-inputs").removeClass("d-none");
				$("#editModal .div-iconselect").addClass("d-none");
				$("#inputImg-image").parent().removeClass("d-none").addClass("d-inline");
				$("#editModal .image-selection").removeClass("d-none");
				$("#editModal .icon-selection").removeClass("d-none");
				$("#editModal .color-circle").removeClass("d-none");

				if(newOrEdit == "edit"){
					
					//get data from the database and populate fields
					var method = db_links.links.findOne({"_id":id}); // load link with the given id
					var name = method["name"];
					var description = method["description"];
					var icon_customImage = method["icon-customImage"];  //the path to a custom image, if empty use icon.
					var icon_class = method["icon-class"];
					var icon_color = method["icon-color"];
					var method_path = method["path"];
					var attachments = method["attachments"];
					var method_default = method["default"];
					var method_type = method["type"];

					//fill input fields
					$("#editModal .txt-linkName").val(name);
					$("#editModal .txt-linkName").closest(".form-group").find(".clear-text").removeClass("d-none");
					
					var old_icon = $("#editModal .editModal-icon").attr("data-iconClass");
					$("#editModal .editModal-icon").removeClass(old_icon).addClass(icon_class);
					$("#editModal .editModal-icon").attr("data-iconClass",icon_class);
					
					var old_color = $("#editModal .editModal-icon").attr("data-colorClass");
					$("#editModal .editModal-icon").removeClass(old_color).addClass(icon_color);
					$("#editModal .editModal-icon").attr("data-colorClass",icon_color);

					$("#editModal .txt-description").val(description);
				

					//check if the given icon_customImage exists, otherwise set placeholder icon
					if(icon_customImage!="" && icon_customImage!="placeholder"){
						try {
							if(fs.existsSync(icon_customImage)) {
								//console.log("The file exists.");
							} else {
								//console.log('The file does not exist.');
								icon_customImage = "placeholder";
							}
						} catch (err) {
							//console.error(err);
						}
					}

					if(icon_customImage == "placeholder"){
						//show image container
						$("#editModal .image-container").removeClass("d-none");
						//hide image
						$("#editModal .editModal-image").addClass("d-none");
						//show placeholder
						$("#editModal .image-placeholder").removeClass("d-none");
						$("#inputImg-image").prop("checked",true);
						$("#inputImg-icon").prop("checked",false);
						$("#editModal .icon-selection").addClass("d-none");
					}

					//Select radio buttom image or icon
					if(icon_customImage =="" && icon_class!=""){
						//show icon
						$("#editModal .icon-container").removeClass("d-none");
						$("#inputImg-image").prop("checked",false);
						$("#inputImg-icon").prop("checked",true);
						$("#editModal .image-selection").addClass("d-none");

						//select icon and color
						var icon = $("#editModal .editModal-icon").attr("data-iconClass");
						$("#editModal .select-icon").removeClass("icon-active");
						$("#editModal .select-icon").find("i." + icon).parent().addClass("icon-active");

						var color = $("#editModal .editModal-icon").attr("data-colorClass");
						$("#editModal .color-circle").removeClass("color-circle-active");
						$("#editModal .color-circle." + color).addClass("color-circle-active");

					}
					if(icon_customImage!="" && icon_customImage!="placeholder"){
						//show image
						$("#editModal .image-container").removeClass("d-none");
						$("#editModal .editModal-image").removeClass("d-none");
						$("#editModal .image-placeholder").addClass("d-none");
						$("#editModal .editModal-image").attr("src", icon_customImage);
						$("#inputImg-image").prop("checked",true);
						$("#inputImg-icon").prop("checked",false);
						$("#editModal .icon-selection").addClass("d-none");
						//fill image input field and show 'X' icon
						$("#input-image").val('');
						$("#editModal .txt-image").val(icon_customImage); 
						$("#editModal .txt-image").closest(".form-group").find(".clear-field").removeClass("d-none");
					}


					//CLEAR file input fields and type
					$("#input-methodfile").val('');
					$("#input-anyfile").val('');
					$("#input-folder").val('');
					$(".inputType-radio input[type='radio']").prop("checked", false);
					$("#editModal .txt-filepath").closest(".form-group").find(".clear-field").removeClass("d-none");

					
					//SET file input fields and type
					$("#editModal .filetype-selection").attr("data-filetype",method_type);
					$("#editModal .filetype-tmpselection").attr("data-filetype",method_type)					
					$("#editModal .txt-filepath").val(method_path);
					

					//CLEAR Attachment fields
					for (i = 1; i < 4; i++) {
						$("#input-attach"+i).val('');
						$("#editModal .txt-attach"+i).val('');
					}

					//SET Attachment fields
					if (attachments) {
						for (k = 0; k < attachments.length; ++k) {
							var index = k+1
							$("#editModal .txt-attach"+index).val(attachments[k]);
							$("#editModal .txt-attach"+index).closest(".form-group").find(".clear-field").removeClass("d-none");
						}
					}

					//SET Version, Build Number and Custom Fields
					$("#editModal .txt-version").val(method["version"] || "");
					$("#editModal .txt-buildnumber").val(method["build-number"] || "");
					var cfObj = method["custom-fields"] || {};
					var cfLines = [];
					var cfKeys = Object.keys(cfObj);
					for(var cf = 0; cf < cfKeys.length; cf++){
						cfLines.push(cfKeys[cf] + "=" + cfObj[cfKeys[cf]]);
					}
					$("#editModal .txt-customfields").val(cfLines.join("\n"));
				}
				if(newOrEdit == "new"){
					var group_id = id;
					//show icon
					$("#editModal .icon-container").removeClass("d-none");
					$("#editModal .editModal-icon").removeClass("d-none");
					$("#inputImg-image").prop("checked",false);
					$("#inputImg-icon").prop("checked",true);
					$("#editModal .image-selection").addClass("d-none");

					//select icon and color
					var icon_class = "fa-dna";
					var icon_color = "color-dark";

					var old_icon = $("#editModal .editModal-icon").attr("data-iconClass");
					$("#editModal .editModal-icon").removeClass(old_icon).addClass(icon_class);
					$("#editModal .editModal-icon").attr("data-iconClass",icon_class);
					
					var old_color = $("#editModal .editModal-icon").attr("data-colorClass");
					$("#editModal .editModal-icon").removeClass(old_color).addClass(icon_color);
					$("#editModal .editModal-icon").attr("data-colorClass",icon_color);

					
					$("#editModal .select-icon").removeClass("icon-active");
					$("#editModal .select-icon").find("i." + icon_class).parent().addClass("icon-active");

					$("#editModal .color-circle").removeClass("color-circle-active");
					$("#editModal .color-circle." + icon_color).addClass("color-circle-active");

					//RESET all input fields
					$("#editModal input[type=file], #editModal input[type=text]").val('');
					$("#editModal .txt-linkName,#editModal .txt-description, #editModal .txt-image").val('');
					$("#editModal .txt-version, #editModal .txt-buildnumber").val('');
					$("#editModal .txt-customfields").val('');
					$("#editModal .clear-text, #editModal .clear-field").addClass("d-none");
				}

				
			}
			if(linkOrGroup == "group"){

				//hide link or image related divs
				$("#editModal .image-container").addClass("d-none");
				$("#editModal .icon-container").removeClass("d-none");
				$("#editModal .div-form").removeClass("d-none");
				$("#editModal .link-inputs").addClass("d-none");
				$("#editModal .div-iconselect").addClass("d-none");
				$("#inputImg-image").parent().removeClass("d-inline").addClass("d-none");
				$("#inputImg-image").prop("checked", false);
				$("#inputImg-icon").prop("checked", true);
				$("#editModal .image-selection").addClass("d-none");
				$("#editModal .icon-selection").removeClass("d-none");
				$("#editModal .color-circle").addClass("d-none");

				var old_color = $("#editModal .editModal-icon").attr("data-colorClass");
				$("#editModal .editModal-icon").removeClass(old_color).addClass("color-dark");
				$("#editModal .color-circle").removeClass("color-circle-active");
				$("#editModal .color-circle.color-dark").addClass("color-circle-active");
				$("#editModal .editModal-icon").attr("data-colorClass","color-dark");

				if(newOrEdit =="edit"){
					//get data from the database and populate fields
					var navgroup = db_groups.groups.findOne({"_id":id}); // loads all custom group
					var group_name = navgroup["name"];
					var group_icon = navgroup["icon-class"];

					//fill input fields
					$("#editModal .txt-linkName").val(group_name);
					var old_icon = $("#editModal .editModal-icon").attr("data-iconClass");
					$("#editModal .editModal-icon").removeClass(old_icon).addClass(group_icon);
					$("#editModal .editModal-icon").attr("data-iconClass",group_icon);

				}
				else{
					//NEW
					//clear fields and default icon
					$("#editModal .txt-linkName").val("");
					var old_icon = $("#editModal .editModal-icon").attr("data-iconClass");
					$("#editModal .editModal-icon").removeClass(old_icon).addClass("fa-dna");
					$("#editModal .editModal-icon").attr("data-iconClass","fa-dna");

				
				}
				
				//update icon selected in the list
				var icon = $("#editModal .editModal-icon").attr("data-iconClass");
				$("#editModal .select-icon").removeClass("icon-active");
				$("#editModal .select-icon").find("i." + icon).parent().addClass("icon-active");
				
				
			}
					
			 $('#editModal').modal();	 

		}
		

		function getDateTime(){
			var tzoffset = (new Date()).getTimezoneOffset() * 60000;
			var localISOTime = (new Date(Date.now() - tzoffset))
			.toISOString()
			.slice(0, 19)
			.replace('T', ' ');
			return ([localISOTime, $.now()]);
		}

		function addLinkToRecent(id){
			//do not display in the Recent group if the link´s parent group is not favorite/not displayed in the navbar
			var group_id = $(".align-items-stretch[data-id='"+ id + "']").attr("data-group-id");
			var parent_navitem = $(".navbarLeft>.custom-group[data-group-id='"+ group_id+"']:not('.d-none'), hidden-nav-items>.custom-group[data-group-id='"+ group_id+"']:not('.d-none')");

			if(parent_navitem.length > 0){
				var thisLinkInRecent = $(".group-container[data-group-id='gRecent'] div.align-items-stretch[data-id='"+ id + "']");
				//Add only if it´s not added yet
				if(thisLinkInRecent.length==0){
					var cloneDiv = $(".align-items-stretch[data-id='"+ id + "']").clone();
					$(".group-container[data-group-id='gRecent']").prepend(cloneDiv);
				}
				//limit the amount of recent links to the max setting...
				$(".group-container[data-group-id='gRecent'] div.align-items-stretch:gt(" + int_maxRecent + ")").remove();
			}

			
		}


		function getRecentMethods(max){
			var tmp_arr =  db_links.links.find();	
			var arrlaststarted = tmp_arr.filter(function (object) { return object["last-startedUTC"] != 0;});
			arrlaststarted.sort((a, b) => a["last-startedUTC"] - b["last-startedUTC"]); //Ascending
			// arrlaststarted.sort((a, b) => b["last-startedUTC"] - a["last-startedUTC"]); //Descending
			arrlaststarted.length = Math.min(arrlaststarted.length, max);  //truncate the array to the max number of Recent allowed.
			return (arrlaststarted);
		}

		function updateLastStarted(id){
			//update started only for non-default links. This is filtered in the link-run-trigger click event
			var arr1 = getDateTime();
			var formattedDateTime = arr1[0];
			var UTCDateTime = arr1[1];

			var dataToSave = {
				"last-started": formattedDateTime,
				"last-startedUTC": UTCDateTime
			};
			//SAVE LINK DATA
			var query = { "_id" : id };
			var options = {
				multi: false,
				upsert: false
			};
			var updated = db_links.links.update(query, dataToSave, options);
		}

		function loadSettings(){
			var settings = db_settings.settings.find()[0]; //get all settings data from settings.json

			//setting - Show on startup
			if(settings["startup-lastOpened"]){
				$("#settings-startupLast").prop("checked", true);
				$("#settings-startupTab").prop("checked", false);
				
			}else{
				$("#settings-startupLast").prop("checked", false);
				$("#settings-startupTab").prop("checked", true);
			}

			//select settings["startup-tab"] in nav bar
			var group_id = settings["startup-tab"];
			var group_name = $(".nav-item[data-group-id='" + group_id + "'").text();
			if(group_name==""){ 
				group_name = "All";
				group_id = "gAll"
			}
			$(".nav-item[data-group-id='" + group_id + "'").trigger("click");
			$(".btn-startupTab").text(group_name);
			

			//setting - Recent
			int_maxRecent = settings["recent-max"];
			console.log("int_maxRecent=" + int_maxRecent);
			$("#dd-maxRecent").text(int_maxRecent);

 
			//Setting - history
			var history_max = $(".dd-historyCleanup a[data-days='"+ settings["history-days"] +"'").text();
			$(".btn-historyMax").text(history_max);
			if(settings["cleanup-action"]=="delete"){
				$("#radio_settingHistory-archive").prop("checked", false);
				$("#radio_settingHistory-delete").prop("checked", true);
			}else{
				$("#radio_settingHistory-archive").prop("checked", true);
				$("#radio_settingHistory-delete").prop("checked", false);
			}
			if(!settings["chk_settingHistoryCleanup"]){
				$("#radio_settingHistory-delete,#radio_settingHistory-archive,.btn-history-cleanup, .btn-historyMax").prop("disabled",true);
			}

			//set all the checkboxes for default shortcuts
			for (var key in settings) {
				if(key.startsWith("chk")){
					//checkboxes for shortcuts are checked by default, only trigger click to uncheck if false.
					if(!settings[key]){ 
						var chkbox = $("#" + key);
						chkbox.prop('checked', false);
						if(chkbox.hasClass("parent-checkbox")){
							//hide item in the navbar of the home screen
							$(".nav-item[data-group-id='"+ chkbox.attr("data-group-id") +"']").addClass("d-none");
						}
						if(chkbox.hasClass("child-checkbox")){
							//hide item in the group-container in home screen
							$(".methods-page").find("div[data-id='" + chkbox.attr("data-id") + "']").addClass("d-none").removeClass("d-flex");
						}
						if(key.toLowerCase().includes("simulation")){
							//checkbox simulation switch
							$("#simulation-switch").prop("disabled", true);
						}
					}
					
				}
			}

			//reset nav bar and hide overflowing nav bar items
			fitNavBarItems();
			fitMainDivHeight();
			updateSortableDivs();
		}

		function saveSetting(key,val){
			var dataToSave = { [key] : val};
			//SAVE LINK DATA
			var query = {"_id":"0"};
			var options = {
				multi: false,
				upsert: false
			};
			var updated = db_settings.settings.update(query, dataToSave, options);
			//  console.log(dataToSave);
			//  console.log(updated);
		}

		function saveLinkKey(id,key,val){
			var dataToSave = { [key] : val};
			//SAVE LINK DATA
			var query = {"_id":id};
			var options = {
				multi: false,
				upsert: false
			};
			var updated = db_links.links.update(query, dataToSave, options);
			//  console.log(dataToSave);
			//  console.log(updated);
		}

		function clearRecentList(){

			//reset last-started keys in the links.json database
			var tmp_arr =  db_links.links.find();	
			var arrlaststarted = tmp_arr.filter(function (object) { return object["last-startedUTC"] != 0;});
			
			var dataToSave={
				"last-startedUTC":0, 
				"last-started":""
			};
			var options = {
				multi: false,
				upsert: false
			};
			for(i=0; i< arrlaststarted.length ; i++){
				var query ={"_id": arrlaststarted[i]["_id"]};
				var updated = db_links.links.update(query, dataToSave, options);
			}
							
			// empty the Recent group
			$(".group-container[data-group-id='gRecent']").empty();

		}

		function historyCleanup(){
			var settings = db_settings.settings.find()[0]; //get all settings data from settings.json
			var archiveDir = settings["history-archive-folder"];
			if(archiveDir==""){archiveDir=os.tmpdir();} //if no dir is given use the default OS temp folder.
			$(".txt-history-archiveDir").val(archiveDir);
			//Set working dir for the method file browse
			$("#input-history-archiveDir").attr("nwworkingdir",archiveDir);
			if(settings["chk_settingHistoryCleanup"]==true){
				var days= parseInt(settings["history-days"]);
				var cleanup_action = settings["cleanup-action"];
				console.log("performing run history cleanup older than "+days+" days...");

				if (cleanup_action == "archive"){
					if(!fs.existsSync(archiveDir)){
						console.log("Aborted cleanup. Destination " + archiveDir + " does not exist");
						return;
					}
				}

				var counter = 0;
				fs.readdir(HxFolder_LogFiles, function(err, files) {
				$(".cleanup-progress-bar").text("0%").css("width","0%").attr("aria-valuenow", 0);
				$(".cleanup-progress-text").text("Cleaning up run logs");
				$(".cleanup-progress").css("display","inline"); //force display after JQuery fadeout if a previous cleanup was run
					// console.log(files.length);
				
					var patt = /(_[a-zA-Z0-9]{32})_HamiltonVectorDB./;
					var arr_tmp = [];

					files.forEach(function(file, index) {
						var ext = path.extname(file);
						if(ext==".mdf" || ext==".ldf"){
							var regexMatch = file.match(patt);
							if(regexMatch){
								if(regexMatch.length>1){
									//if it´s an .mdf or .ldf , detach the HamiltonVectorDb database file and retry
									//Detach the given database name
									//input :  "HamiltonVectorDb_<run_id>"
									//return :  -1 if error, 0 no error
									var runDb = "HamiltonVectorDB" + regexMatch[1];
									if(arr_tmp.indexOf(runDb)==-1){
										arr_tmp.push(runDb);
										DetachDatabase(runDb,function (error, result){
											if(!error){
												console.log("Detaching DB result = " + result);
												if(result=="-1"){
													console.log ("cannot detach or previously detached : " + file);
												}
											}
										});
									}
								}
							}
						}
							var currentPath = path.join(HxFolder_LogFiles,file);
							var bool_processFile = false;
							fs.stat(currentPath, function(err, stats) {
										if (err) {
												console.log( "error getting stat from file :" + currentPath);
										}else{
										  bool_processFile = true;
										}

									if(bool_processFile){
											const today = new Date();
											endtime = new Date(stats.mtime);
											endtime.setDate(endtime.getDate() + days);

										if (today > endtime) {
											//   console.log(currentPath);
											  if(cleanup_action=="delete"){
												fs.unlink(currentPath, (err) => {
													counter++;
													cleanupProgress(counter, files.length);
												  if (err) {
													console.log( "error deleting file :" + currentPath);
												  }
												  //file deleted OK
												//   console.log(currentPath);
												  });
											  }
											  if(cleanup_action=="archive"){
													var destinationPath = path.join(archiveDir,file);
													fs.rename(currentPath, destinationPath, function (err) {
														counter++;
														cleanupProgress(counter, files.length);
													  if (err) {
														console.log("error moving file :" + currentPath);
													  } else {
														//file moved OK
														 console.log("Moved at first try = " + destinationPath);
													  }
													});
											  }
										}else{
											counter++;
											cleanupProgress(counter, files.length);
										}
									}else{
										counter++;
										cleanupProgress(counter, files.length);
									}
							 }); //end fs.stat						
			       });//end forEach loop
			});//end fs.readdir
			}
		}


		

		function cleanupProgress(count, total){
			var percentage = (100*count/total).toFixed(0);
			$(".cleanup-progress-bar").text(percentage + "%").css("width",percentage + "%").attr("aria-valuenow", percentage);
			if(count==total){
				$(".cleanup-progress-text").text("Run log cleanup completed!");
				setTimeout(function (){
					$(".cleanup-progress").fadeOut();
				},4000);
				
			}
		}

		function updateSimulationSwitch(sim){
			if(sim==1){
				$(".sim-on-off").text("On");
				$("#simulation-switch").prop("checked",true);
			}else{
				$(".sim-on-off").text("Off");
				$("#simulation-switch").prop("checked",false);
			}
		}

			function HandleFunctionProtection(error, result) {
					// console.log("hey HandleFunctionProtection");
					if (error) {
						console.log(error);
					} else{
						functionProtection=parseInt(result);
						if(functionProtection==1){
							console.log("Function Protection=" + functionProtection);
							GetUseInternalLogOn( "null", HandleUseInternalLogon);
						}else{
							//user login disabled. Free ride!
							$(".btn-settings").removeClass("d-none");
						}
					}  
			}

			function HandleUseInternalLogon(error, result) {
					// console.log("hey HandleUseInternalLogon");
					if (error) {
						console.log(error);
					} else{
						internalLogon=parseInt(result);
						if(internalLogon===1){ 
							//HAMILTON Authentication. Force log off before going any further
							LogOff( "", function(error, result) {
								if (error) {
									console.log(error);
								} else{
									console.log("Current user has been logged off'..." + result);
								}  
							});
						}
						GetCurrentAccessRightOS("null", HandleAccessRights);

					}  
			}




			// LogOff( "", function(error, result) {
			//         console.log("hey");
			//         if (error) {
			//             console.log(error);
			//         } else{
			//              console.log("Current user has been logged off'..." + result);
			//         }  
			// });
			// LogOn( "testuser,123456", function(error, result) {
			//         console.log("hey");
			//         if (error) {
			//             console.log(error);
			//         } else{
			//              console.log("Log on:" + result);
			//         }  
			// });

			function SetUser(username, role){
				if(username!=""){
					$(".username-container").removeClass("d-none");
					$(".username-name").text(username);
					$(".username-role").text("(" + role + ")");
					if(accessRights>1){ //Only programmer and admin can tweak settings
						isUserAdmin = false;
						$(".btn-settings").addClass("d-none");
					}else{
						$(".btn-settings").removeClass("d-none");
					}
					if(internalLogon==0){
						//OS Authentication, hide logoff button
						$(".username-logoff").addClass("d-none").removeClass("d-inline"); 
					}
					else{
						//Hamilton Authentication, show logoff button
						$(".username-logoff").removeClass("d-none").addClass("d-inline"); 
					}
				}
				else{
					$(".btn-settings").removeClass("d-none");
					$(".username-container").addClass("d-none");
				}
				
			}

			function HandleAccessRights(error, result) {
					// console.log("hey GetCurrentAccessRights");
					if (error) {
						console.log(error);
					} else{
						accessRights=parseInt(result);
						console.log("GetCurrentAccessRights=" + result + " --- " + EnumAccessRights[accessRights]);
						if(functionProtection===1){ 
							//User access control enabled

							if(accessRights===4){
							//No access granted
								if(internalLogon===1){ 
								//HAMILTON Authentication.  Show VENUS log on dialog
									console.log("uses HAmilton Authentication");
									LogOnDialog("null", HandleLogOnDialog);
								}
								if(internalLogon===0){
									//OS Authentication
									console.log("uses Windows Authentication");
									GetCurrentUsernameOS( "", HandleGetUsername);
								}
							}
							else{
								// User has some level rights
								console.log("USER WITH RIGHTS TO OPERATE AS " + EnumAccessRights[accessRights]);
								GetCurrentUsernameOS( "", HandleGetUsername);
							}

						}
						else{
							//User access control disabled
							console.log("No user control enabled,  OPERATE AS " + EnumAccessRights[accessRights]);
							SetUser("", "");
						}
					} 
			}

			function HandleLogOnDialog(error, result) {
					// console.log("hey HandleLogOnDialog");
					if (error) {
						console.log(error);
					} else{
						console.log("Showing Logon Dialog " + result);
						var dialogReturn=parseInt(result);
						if(dialogReturn===1){
							//login succesful
							console.log("Login succesful !!!");
							GetCurrentAccessRightOS("null", HandleAccessRights);
						}
						if(dialogReturn===2){
							//login dialog cancelled
							console.log("Login failed. Restart application to retry login");

							if(bool_isHamUserChangeClick){
								//do nothing if the dialog is cancelled after trying a user change.
							}
							else{
								//quit app if the Hamilton login dialog is cancelled on startup
								gui.App.closeAllWindows();
								win.close(true);
							}
							
						}
					}  
			}

			function HandleGetUsername(error, result){
				// console.log("hey GetCurrentUsername");
					if (error) {
						console.log(error);
					} else{
						console.log("GetCurrentUsernameOS=" + result);
						SetUser(result, EnumAccessRights[accessRights]);
					}
			}


		function scanLinksDirectory() {
			// Check if the links directory exists
			if (!fs.existsSync(linksDirectoryPath)) {
				console.log("Links directory does not exist: " + linksDirectoryPath);
				return;
			}

			// Find or create the "Libraries" group (diskdb auto-generates _id, so find by name)
			var libGroup = db_groups.groups.findOne({"name": "Libraries", "source": "directory-scan"});
			var groupId;

			if (!libGroup) {
				var savedGroup = db_groups.groups.save({
					"name": "Libraries",
					"icon-class": "fa-book",
					"default": false,
					"navbar": "left",
					"favorite": true,
					"source": "directory-scan"
				});
				groupId = savedGroup._id;
			} else {
				groupId = libGroup._id;
			}

			// Read all files from the directory
			var files;
			try {
				files = fs.readdirSync(linksDirectoryPath);
			} catch (err) {
				console.log("Error reading links directory: " + err);
				return;
			}

			var allLinks = db_links.links.find();
			var newLinkIds = [];
			var currentFilePaths = [];

			files.forEach(function(file) {
				var filePath = path.join(linksDirectoryPath, file);
				try {
					var stats = fs.statSync(filePath);
					if (stats.isFile()) {
						currentFilePaths.push(filePath);

						// Check if a link with this path already exists
						var existingLink = allLinks.find(function(link) {
							return link.path === filePath;
						});

						if (!existingLink) {
							var fileName = path.basename(file, path.extname(file));
							var saved = db_links.links.save({
								"name": fileName,
								"description": "",
								"icon-customImage": "",
								"icon-class": "fa-file-code",
								"icon-color": "color-blue",
								"path": filePath,
								"type": "file",
								"attachments": [],
								"default": false,
								"favorite": true,
								"last-started": "",
								"last-startedUTC": 0,
								"source": "directory-scan"
							});
							newLinkIds.push(saved._id);
						}
					}
				} catch (err) {
					console.log("Error processing file: " + file + " - " + err);
				}
			});

			// Get or create the tree entry for the Libraries group using the actual group _id
			var treeEntry = db_tree.tree.findOne({"group-id": groupId});

			if (treeEntry) {
				var existingMethodIds = treeEntry["method-ids"] || [];

				// Keep manually-added links and auto-scanned links whose files still exist
				var validIds = [];
				existingMethodIds.forEach(function(id) {
					var link = db_links.links.findOne({"_id": id});
					if (link) {
						if (link.source === "directory-scan") {
							// Auto-scanned link: keep only if file still exists in directory
							if (currentFilePaths.indexOf(link.path) !== -1) {
								validIds.push(id);
							} else {
								db_links.links.remove({"_id": id});
							}
						} else {
							// Manually added link: always keep
							validIds.push(id);
						}
					}
				});

				var updatedMethodIds = validIds.concat(newLinkIds);
				db_tree.tree.update({"group-id": groupId}, {"method-ids": updatedMethodIds}, {multi: false, upsert: false});
			} else {
				// No tree entry yet — collect IDs of all scanned links already in the DB
				var existingScannedIds = [];
				allLinks.forEach(function(link) {
					if (link.source === "directory-scan" && currentFilePaths.indexOf(link.path) !== -1) {
						existingScannedIds.push(link._id);
					}
				});
				var allMethodIds = existingScannedIds.concat(newLinkIds);
				db_tree.tree.save({
					"group-id": groupId,
					"method-ids": allMethodIds,
					"locked": false
				});
			}

			// Clean up any orphaned tree entries referencing old invalid group IDs (e.g. "gLibraries")
			var allTreeEntries = db_tree.tree.find();
			allTreeEntries.forEach(function(entry) {
				var gid = entry["group-id"];
				if (gid !== groupId && !db_groups.groups.findOne({"_id": gid})) {
					// Orphaned tree entry with no matching group - remove it
					db_tree.tree.remove({"_id": entry._id});
				}
			});

			console.log("Scanned links directory: " + linksDirectoryPath + " - added " + newLinkIds.length + " new links, group id: " + groupId);
		}

		function initVENUSData(){

			GetVENUSPathsFromRegistry("null",function (error, result){
				var jsondata = JSON.parse(result.toString());
				// jsondata contains bin-folder, cfg-folder, lib-folder, log-folder, lbw-folder, sys-folder,met-folder
				
				saveLinkKey("bin-folder","path",jsondata["bin-folder"]);
				saveLinkKey("cfg-folder","path",jsondata["cfg-folder"]);
				saveLinkKey("lbw-folder","path",jsondata["lbw-folder"]);
				saveLinkKey("lib-folder","path",jsondata["lib-folder"]);
				saveLinkKey("log-folder","path",jsondata["log-folder"]);
				saveLinkKey("met-folder","path",jsondata["met-folder"]);
			
				HxFolder_LogFiles = jsondata["log-folder"];
				HxFolder_Methods = jsondata["met-folder"];
				HxFolder_Bin = jsondata["bin-folder"];
				HxRun = jsondata["bin-folder"] + "\\" + HxRun;
			
				saveLinkKey("method-editor","path",jsondata["bin-folder"] + "\\" + HxMethodEditor);
				saveLinkKey("lc-editor","path",jsondata["bin-folder"] + "\\" + HxLiquidEditor);
				saveLinkKey("lbw-editor","path",jsondata["bin-folder"] + "\\" + HxLabwareEditor);
				saveLinkKey("hsl-editor","path",jsondata["bin-folder"] + "\\" + HxHSLEditor);
				saveLinkKey("sysCfg-editor","path",jsondata["bin-folder"] + "\\" + HxConfigEditor);
				saveLinkKey("run-control","path", HxRun);
				saveLinkKey("ham-version","path",jsondata["bin-folder"] + "\\" + HxVersion);
			
				//Set working dir for the method file browse
				$("#input-methodfile").attr("nwworkingdir",HxFolder_Methods);
				// console.log(jsondata);
			})

			GetSimulation("null",function (error, result){

				console.log("simulation=" + result);
				updateSimulationSwitch(result);
			
			})
			
			 GetFunctionProtection("null",HandleFunctionProtection);
			
		}
	

		function goVideo(src, str){
		
			// $("#videoModal .modal-title").text(str);
			var myPlayer = videojs("#modal-video");
			myPlayer.src("js/custom/" + src);
			myPlayer.play();
			myPlayer.currentTime(0);
			myPlayer.fluid(true);
			myPlayer.controls(true);
			myPlayer.loop(true);
			$('#videoModal').modal();
		}

		$('#videoModal').on("hidden.bs.modal", function(){
			if(win.isFullscreen){
				win.leaveFullscreen();
			}
		});


		
        //**************************************************************************************
        //******  FUNCTION DECLARATIONS END ****************************************************
        //**************************************************************************************
		


		